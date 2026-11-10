/**
 * Sentinel AI request-guard SDK — core HTTP client.
 *
 * Zero runtime dependencies: it relies on the global `fetch` available in
 * Node.js 18+ (and in the Next.js Edge runtime). The API key is transmitted
 * ONLY through the `X-API-Key` header, which is the exact scheme validated by
 * modules/sites.py, modules/policies.py, modules/ratelimit.py,
 * modules/botguard.py and modules/acl.py.
 *
 * Every call resolves to a uniform envelope instead of throwing, so an inline
 * guard can always make a decision:
 *
 *   { ok: true,  result: <server result object>, raw: <full payload> }
 *   { ok: false, error: { code, message, status }, result: <fallback verdict> }
 *
 * When the service cannot be reached the client applies `failureMode`:
 *   'open'   (default) -> result.decision 'allow'  + result.unavailable true
 *   'closed'           -> result.decision 'block'  + result.unavailable true
 *   'throw'            -> the SentinelError is re-thrown to the caller
 */

export const FAILURE_MODES = ['open', 'closed', 'throw'];

export const ERROR_CODES = [
  'configuration',
  'timeout',
  'network_error',
  'unauthorized',
  'http_error',
  'invalid_response',
];

export class SentinelError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'SentinelError';
    this.code = code;
    this.status = options.status ?? null;
    if (options.cause) {
      this.cause = options.cause;
    }
  }
}

/** Drop undefined/null entries so the JSON body only carries explicit values. */
function compact(source) {
  const out = {};
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && value !== null) {
      out[key] = value;
    }
  }
  return out;
}

export class SentinelClient {
  /**
   * @param {object}   options
   * @param {string}   options.baseUrl     Sentinel AI origin, e.g. "https://sentinel.example.com".
   * @param {string}   options.apiKey      Site API key (`snt_...`) sent as X-API-Key.
   * @param {number}   [options.timeoutMs] Per-request budget. Keep it well below your own request budget.
   * @param {string}   [options.failureMode] 'open' | 'closed' | 'throw'.
   * @param {object}   [options.logger]    Optional logger with a `.warn(message)` method.
   * @param {Function} [options.fetchImpl] Override for tests or custom runtimes.
   */
  constructor(options = {}) {
    const {
      baseUrl,
      apiKey,
      timeoutMs = 1000,
      failureMode = 'open',
      logger = null,
      fetchImpl = null,
    } = options;

    if (typeof baseUrl !== 'string' || baseUrl.trim() === '') {
      throw new SentinelError('configuration', 'baseUrl is required, e.g. "https://sentinel.example.com"');
    }
    if (typeof apiKey !== 'string' || apiKey.trim() === '') {
      throw new SentinelError('configuration', 'apiKey is required; it is sent as the X-API-Key header');
    }
    if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new SentinelError('configuration', 'timeoutMs must be a positive number of milliseconds');
    }
    if (!FAILURE_MODES.includes(failureMode)) {
      throw new SentinelError('configuration', `failureMode must be one of: ${FAILURE_MODES.join(', ')}`);
    }

    const fetchFn = fetchImpl || globalThis.fetch;
    if (typeof fetchFn !== 'function') {
      throw new SentinelError('configuration', 'no fetch implementation available; pass `fetchImpl` explicitly');
    }

    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.failureMode = failureMode;
    this.logger = logger;
    this.fetchImpl = fetchFn;
  }

  // --- public API ----------------------------------------------------------

  /** POST /api/acl/check — allow/block lists. Optional `ip` overrides the caller IP. */
  checkAcl({ path, ip } = {}) {
    return this._guard(() => this._request('POST', '/api/acl/check', compact({ path, ip })));
  }

  /** POST /api/ratelimit/check — fixed-window rate limiting. */
  checkRateLimit({ path } = {}) {
    return this._guard(() => this._request('POST', '/api/ratelimit/check', compact({ path })));
  }

  /** POST /api/policies/evaluate — path-based policies. */
  evaluatePolicy({ path } = {}) {
    return this._guard(() => this._request('POST', '/api/policies/evaluate', compact({ path })));
  }

  /**
   * POST /api/botguard/evaluate — monitor-only automation scoring.
   * `headers` forwards the END USER's header values, which the server uses in
   * preference to the headers of this SDK request.
   */
  evaluateBot({ path, method, headers } = {}) {
    return this._guard(() => this._request('POST', '/api/botguard/evaluate', compact({ path, method, headers })));
  }

  /** GET /api/apikey-info — validates the key and returns the owning site. */
  verifyKey() {
    return this._guard(() => this._request('GET', '/api/apikey-info'));
  }

  // --- internals -----------------------------------------------------------

  async _guard(operation) {
    try {
      const payload = await operation();
      return {
        ok: true,
        result: Object.prototype.hasOwnProperty.call(payload, 'result') ? payload.result : payload,
        raw: payload,
      };
    } catch (error) {
      if (this.failureMode === 'throw' || !(error instanceof SentinelError)) {
        throw error;
      }
      const failedOpen = this.failureMode === 'open';
      this._warn(`check failed (${error.code}: ${error.message}); failing ${failedOpen ? 'open' : 'closed'}`);
      return {
        ok: false,
        error: { code: error.code, message: error.message, status: error.status },
        result: {
          decision: failedOpen ? 'allow' : 'block',
          action_taken: failedOpen ? 'allowed' : 'blocked',
          reason: 'sentinel_unavailable',
          unavailable: true,
        },
      };
    }
  }

  async _request(method, endpoint, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}${endpoint}`, {
          method,
          headers: body === undefined
            ? { 'X-API-Key': this.apiKey }
            : { 'X-API-Key': this.apiKey, 'Content-Type': 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (cause) {
        if (cause && cause.name === 'AbortError') {
          throw new SentinelError('timeout', `no response within ${this.timeoutMs}ms`, { cause });
        }
        throw new SentinelError('network_error', `service unreachable (${cause && cause.message})`, { cause });
      }

      if (!response.ok) {
        const code = response.status === 401 || response.status === 403 ? 'unauthorized' : 'http_error';
        throw new SentinelError(code, `service responded with HTTP ${response.status}`, { status: response.status });
      }

      let payload;
      try {
        payload = await response.json();
      } catch (cause) {
        throw new SentinelError('invalid_response', 'service did not return valid JSON', {
          status: response.status,
          cause,
        });
      }
      if (payload === null || typeof payload !== 'object') {
        throw new SentinelError('invalid_response', 'service returned an unexpected payload shape', {
          status: response.status,
        });
      }
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }

  _warn(message) {
    if (this.logger && typeof this.logger.warn === 'function') {
      this.logger.warn(`[sentinel-sdk] ${message}`);
    }
  }
}
