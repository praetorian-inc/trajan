/**
 * Trajan Browser Security Scanner - JavaScript Bridge
 *
 * This module provides a comprehensive Promise-based API for calling Go WASM functions.
 * It handles WASM initialization, error handling, async patterns, and progress tracking.
 */

class TrajanBridge {
  constructor() {
    this.wasmReady = false;
    this.initPromise = null;
    this.apiInitialized = false;
    this.initError = null;
  }

  /**
   * Initialize the WASM module
   * @returns {Promise<void>}
   */
  async init() {
    if (this.wasmReady) {
      return;
    }

    if (this.initPromise) {
      return this.initPromise;
    }

    this.initPromise = this._loadWasm();
    await this.initPromise;
    this.wasmReady = true;

    // Initialize the Go-side API (storage, config, etc.)
    if (!this.apiInitialized) {
      await this.initialize();
      this.apiInitialized = true;
    }
  }

  /**
   * Load and instantiate the WASM module
   * @private
   */
  async _loadWasm() {
    try {
      // Check if wasm_exec.js is loaded
      if (typeof Go === 'undefined') {
        throw new Error('wasm_exec.js not loaded. Include it before bridge.js');
      }

      const go = new Go();

      console.log('📦 Loading WASM module...');
      const startTime = performance.now();

      let result;

      // Use streaming instantiation if available (faster for large WASM files)
      if (typeof WebAssembly.instantiateStreaming === 'function') {
        try {
          console.log('Using WebAssembly.instantiateStreaming for faster load...');
          const response = await fetch('trajan.wasm');

          // Verify response is OK before streaming
          if (!response.ok) {
            throw new Error(`Failed to fetch trajan.wasm: ${response.statusText}`);
          }

          // Check if proper MIME type is set (required for streaming)
          const contentType = response.headers.get('Content-Type');
          if (contentType === 'application/wasm') {
            // Use streaming compilation (fastest path)
            result = await WebAssembly.instantiateStreaming(response, go.importObject);
          } else {
            // Fall back to buffer instantiation if MIME type is wrong
            console.warn(`WASM served with incorrect MIME type '${contentType}', falling back to buffer instantiation`);
            const buffer = await response.arrayBuffer();
            result = await WebAssembly.instantiate(buffer, go.importObject);
          }
        } catch (streamError) {
          // If streaming fails, fall back to traditional method
          console.warn('Streaming instantiation failed, falling back to buffer method:', streamError);
          const response = await fetch('trajan.wasm');
          if (!response.ok) {
            throw new Error(`Failed to fetch trajan.wasm: ${response.statusText}`);
          }
          const buffer = await response.arrayBuffer();
          result = await WebAssembly.instantiate(buffer, go.importObject);
        }
      } else {
        // Browser doesn't support streaming, use traditional method
        console.log('WebAssembly.instantiateStreaming not available, using buffer instantiation...');
        const response = await fetch('trajan.wasm');
        if (!response.ok) {
          throw new Error(`Failed to fetch trajan.wasm: ${response.statusText}`);
        }
        const buffer = await response.arrayBuffer();
        result = await WebAssembly.instantiate(buffer, go.importObject);
      }

      const loadTime = ((performance.now() - startTime) / 1000).toFixed(2);
      console.log(`📦 WASM module loaded in ${loadTime}s`);

      // Run the Go program (this sets up the global functions)
      go.run(result.instance);

      // Wait a tick for the Go runtime to set up global functions
      await new Promise(resolve => setTimeout(resolve, 100));

      // Verify core API functions are available
      const requiredFunctions = [
        'trajanInitialize',
        'trajanStartScan',
        'trajanExecuteAttack',
        'trajanConfigGet',
        'trajanConfigSet',
        'trajanValidateToken'
      ];

      for (const fnName of requiredFunctions) {
        if (typeof window[fnName] !== 'function') {
          throw new Error(`${fnName} function not exported from WASM`);
        }
      }

      console.log('✅ Trajan WASM module loaded successfully');
    } catch (error) {
      console.error('❌ Failed to load WASM module:', error);
      this.initError = error.message;
      throw error;
    }
  }

  /**
   * Initialize Trajan API (storage, config, registry)
   * @returns {Promise<void>}
   */
  async initialize() {
    if (!this.wasmReady) {
      await this.init();
    }

    return window.trajanInitialize();
  }

  /* ==================== ANALYSIS API ==================== */

  /**
   * Start a vulnerability scan
   * @param {string} target - Target repository URL
   * @param {Object} options - Scan options
   * @param {string} options.platform - Platform ('github', 'gitlab', etc.)
   * @param {string} options.token - Authentication token
   * @param {number} options.concurrent - Concurrent requests
   * @param {boolean} options.includeArchived - Include archived repos
   * @param {Function} options.onProgress - Progress callback (percent, message)
   * @returns {Promise<{scanId: string}>}
   */
  async startScan(target, options = {}) {
    if (!this.wasmReady) {
      await this.init();
    }

    return window.trajanStartScan(target, options);
  }

  /**
   * Get scan results by scan ID
   * @param {string} scanId - Scan identifier
   * @returns {Promise<{findings: Array}>}
   */
  async getResults(scanId) {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanGetResults(scanId);
    // Parse JSON string to object
    if (result.findings && typeof result.findings === 'string') {
      result.findings = JSON.parse(result.findings);
    }
    return result;
  }

  /**
   * Export scan results in specified format
   * @param {string} scanId - Scan identifier
   * @param {string} format - Export format ('json' or 'sarif')
   * @returns {Promise<{data: string}>}
   */
  async exportResults(scanId, format = 'json') {
    if (!this.wasmReady) {
      await this.init();
    }

    return window.trajanExportResults(scanId, format);
  }

  /**
   * Cancel active scan
   * @returns {{success: boolean}}
   */
  cancelScan() {
    if (!this.wasmReady) {
      return { success: false, error: 'WASM not initialized' };
    }

    return window.trajanCancelScan();
  }

  /* ==================== ATTACK API ==================== */

  /**
   * Execute an attack plugin
   * @param {string} plugin - Plugin name
   * @param {string} target - Target repository
   * @param {Object} options - Attack options
   * @param {string} options.token - GitHub token
   * @param {boolean} options.authorized - Authorization confirmation (REQUIRED)
   * @param {boolean} options.saveSession - Save session for later cleanup
   * @param {boolean} options.dryRun - Dry run mode
   * @param {string} options.branch - Branch name (optional)
   * @param {boolean} options.cleanup - Auto-cleanup after execution
   * @param {string} options.payload - Custom payload
   * @param {Object} options.metadata - Additional metadata
   * @param {Function} options.onProgress - Progress callback (message)
   * @returns {Promise<{result: Object}>}
   */
  async executeAttack(plugin, target, options = {}) {
    if (!this.wasmReady) {
      await this.init();
    }

    // Validate authorization
    if (!options.authorized) {
      throw new Error('Attack execution requires explicit authorization (set authorized: true)');
    }

    const result = await window.trajanExecuteAttack(plugin, target, options);

    // Parse JSON string to object
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }

    return result;
  }

  /**
   * Cleanup attack session artifacts
   * @param {string} sessionId - Session identifier
   * @param {string} token - GitHub token
   * @returns {Promise<{summary: Object}>}
   */
  async cleanupSession(sessionId, token) {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanCleanupSession(sessionId, token);

    // Check for error in result
    if (result && result.error) {
      throw new Error(result.error);
    }

    // Parse JSON string to object
    if (result.summary && typeof result.summary === 'string') {
      result.summary = JSON.parse(result.summary);
    }

    return result;
  }

  /**
   * Get attack session status
   * @param {string} sessionId - Session identifier
   * @returns {Promise<{session: Object}>}
   */
  async getSessionStatus(sessionId) {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanGetSessionStatus(sessionId);

    // Parse JSON string to object
    if (result.session && typeof result.session === 'string') {
      result.session = JSON.parse(result.session);
    }

    return result;
  }

  /**
   * List available attack plugins
   * @returns {Promise<{plugins: Array}>}
   */
  async listAttackPlugins() {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanListAttackPlugins();

    // Parse JSON string to object
    if (result.plugins && typeof result.plugins === 'string') {
      result.plugins = JSON.parse(result.plugins);
    }

    return result;
  }

  /**
   * List all attack sessions
   * @returns {Promise<{sessions: Array}>}
   */
  async listSessions() {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanListSessions();

    // Parse JSON string to object
    if (result.sessions && typeof result.sessions === 'string') {
      result.sessions = JSON.parse(result.sessions);
    }

    return result;
  }

  /* ==================== RECON API ==================== */

  /**
   * Scan organization secrets and variables
   * @param {string} target - Organization name
   * @param {Object} options - Scan options
   * @param {string} options.token - Authentication token
   * @param {Function} options.onProgress - Progress callback (percent, message)
   * @returns {Promise<{result: Object}>}
   * @deprecated Use enumerate('github', 'secrets', {token, target}) instead
   */
  async scanSecrets(target, options = {}) {
    console.warn('scanSecrets is deprecated, use enumerate("github", "secrets", options) instead');
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanScanSecrets(target, options);
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }
    return result;
  }

  /**
   * Scan organization for self-hosted runners and workflows
   * @param {string} target - Organization name
   * @param {Object} options - Scan options
   * @param {string} options.token - Authentication token
   * @param {Function} options.onProgress - Progress callback (percent, message)
   * @returns {Promise<{result: Object}>}
   * @deprecated Use enumerate('github', 'runners', {token, target}) instead
   */
  async scanRunners(target, options = {}) {
    console.warn('scanRunners is deprecated, use enumerate("github", "runners", options) instead');
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanScanRunners(target, options);
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }
    return result;
  }

  /**
   * Self-enumerate token permissions, orgs, and runner access
   * @param {Object} options - Enumeration options
   * @param {string} options.token - Authentication token
   * @param {Function} options.onProgress - Progress callback (percent, message)
   * @returns {Promise<{result: Object}>}
   * @deprecated Use enumerate('github', 'repos', options) instead
   */
  async selfEnumerate(options = {}) {
    console.warn('selfEnumerate is deprecated, use enumerate("github", "repos", options) instead');
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanSelfEnumerate(options);
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }
    return result;
  }

  /**
   * Enumerate platform resources (unified API for GitHub/GitLab/Azure DevOps)
   * @param {string} platform - Platform ('github', 'gitlab', 'azuredevops')
   * @param {string} operation - Operation type ('repos', 'secrets', 'runners', 'projects', etc.)
   * @param {Object} options - Enumeration options
   * @param {string} options.token - Authentication token (required)
   * @param {string} options.target - Target org/group/project (conditional)
   * @param {string} options.baseURL - Custom base URL for self-hosted (optional)
   * @param {Function} options.onProgress - Progress callback (percent, message)
   * @returns {Promise<{result: Object}>}
   */
  async enumerate(platform, operation, options = {}) {
    if (!this.wasmReady) {
      await this.init();
    }

    // Validate required parameters
    if (!platform || !operation) {
      throw new Error('Platform and operation are required');
    }

    if (!options.token) {
      throw new Error('Authentication token is required');
    }

    const result = await window.trajanEnumerate(platform, operation, options);

    // Parse JSON string result
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }

    return result;
  }

  /* ==================== SEARCH API ==================== */

  /**
   * Search for self-hosted runner workflows via GitHub or SourceGraph
   * @param {string} query - Search query
   * @param {Object} options - Search options
   * @param {string} options.token - Authentication token (required for GitHub)
   * @param {string} options.source - Search source ('github' or 'sourcegraph')
   * @param {string} options.org - Organization filter
   * @returns {Promise<{result: Object}>}
   */
  async search(query, options = {}) {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanSearch(query, options);
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }
    return result;
  }

  /* ==================== CONFIGURATION API ==================== */

  /**
   * Set configuration value
   * @param {string} key - Configuration key (dot-notation)
   * @param {*} value - Configuration value
   * @returns {Promise<{success: boolean}>}
   */
  async configSet(key, value) {
    if (!this.wasmReady) {
      await this.init();
    }

    return window.trajanConfigSet(key, value);
  }

  /**
   * Get configuration value
   * @param {string} key - Configuration key (dot-notation)
   * @returns {Promise<{value: *}>}
   */
  async configGet(key) {
    if (!this.wasmReady) {
      await this.init();
    }

    return window.trajanConfigGet(key);
  }

  /* ==================== TOKEN VALIDATION API ==================== */

  /**
   * Validate an authentication token
   * @param {Object} options - Validation options
   * @param {string} options.token - Authentication token
   * @param {string} options.platform - Platform ('github', 'gitlab', etc.)
   * @param {string} options.url - Custom instance URL (for self-hosted)
   * @returns {Promise<{result: Object}>}
   */
  async validateToken(options = {}) {
    if (!this.wasmReady) {
      await this.init();
    }

    const result = await window.trajanValidateToken(options);
    if (result.result && typeof result.result === 'string') {
      result.result = JSON.parse(result.result);
    }
    return result;
  }

  /* ==================== UTILITY METHODS ==================== */

  /**
   * Check if WASM is ready
   * @returns {boolean}
   */
  isReady() {
    return this.wasmReady && this.apiInitialized;
  }

  /**
   * Get build version information
   * @returns {Promise<{version: string, buildTime: string, gitCommit: string}>}
   */
  async getVersion() {
    if (!this.wasmReady) {
      await this.init();
    }

    if (typeof window.trajanGetVersion !== 'function') {
      throw new Error('trajanGetVersion function not exported from WASM');
    }

    return window.trajanGetVersion();
  }
}

// Export singleton instance
const trajan = new TrajanBridge();

// Make available globally for HTML usage
if (typeof window !== 'undefined') {
  window.trajan = trajan;
}
