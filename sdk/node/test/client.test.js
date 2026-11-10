import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { SentinelClient, SentinelError, createGuard } from '../src/index.js';

const API_KEY = 'snt_test_key_do_not_log';

/**
 * Spin up a throwaway HTTP server; `handler(req, body)` returns
 * `{ status?, payload?, contentType? }`. The server is always torn down,
 * including sockets kept alive by fetch.
 */
async function withServer(handler, run) {
  const server = http.createServer((req, res) => {
    res.on('error', () => {});
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', async () => {
      let reply;
      try {
        reply = await handler(req, body);
      } catch (error) {
        reply = { status: 500, payload: { error: String(error) } };
      }
      if (res.destroyed || res.writableEnded) {
        return;
      }
      const payload = reply?.payload ?? {};
      res.writeHead(reply?.status ?? 200, { 'Content-Type': reply?.contentType ?? 'application/json' });
      res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    return await run(baseUrl);
  } finally {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise((resolve) => server.close(resolve));
  }
}

function clientFor(baseUrl, overrides = {}) {
  return new SentinelClient({ baseUrl, apiKey: API_KEY, ...overrides });
}

/** Route table keyed by "METHOD /path"; a route may be a reply or a function. */
function router(routes, hits = []) {
  return async (req, body) => {
    const key = `${req.method} ${req.url}`;
    hits.push(key);
    const route = routes[key];
    if (!route) {
      return { status: 404, payload: { error: 'not found' } };
    }
    return typeof route === 'function' ? route(JSON.parse(body || '{}'), req) : route;
  };
}

const ok = (result) => ({ payload: { result } });
const slow = (delayMs) => async () => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  return ok({});
};

// --- configuration ---------------------------------------------------------

test('rejects incomplete configuration at construction time', () => {
  assert.throws(() => new SentinelClient({ apiKey: 'k' }), (e) => e instanceof SentinelError && e.code === 'configuration');
  assert.throws(() => new SentinelClient({ baseUrl: 'http://x' }), (e) => e.code === 'configuration');
  assert.throws(() => new SentinelClient({ baseUrl: 'http://x', apiKey: 'k', timeoutMs: 0 }), (e) => e.code === 'configuration');
  assert.throws(() => new SentinelClient({ baseUrl: 'http://x', apiKey: 'k', failureMode: 'maybe' }), (e) => e.code === 'configuration');
  assert.throws(() => new SentinelClient({ baseUrl: 'http://x', apiKey: 'k', fetchImpl: 'nope' }), (e) => e.code === 'configuration');
});

test('strips trailing slashes from baseUrl', () => {
  const client = clientFor('http://example.test///');
  assert.equal(client.baseUrl, 'http://example.test');
});

// --- happy paths -----------------------------------------------------------

test('checkAcl sends the key and payload, then unwraps result', async () => {
  let seen = null;
  await withServer(router({
    'POST /api/acl/check': (body, req) => {
      seen = { key: req.headers['x-api-key'], body };
      return ok({ matched: true, list_type: 'block', action_taken: 'blocked', enforced: true });
    },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).checkAcl({ path: '/admin', ip: '203.0.113.9' });
    assert.equal(out.ok, true);
    assert.equal(out.result.action_taken, 'blocked');
    assert.equal(seen.key, API_KEY);
    assert.deepEqual(seen.body, { path: '/admin', ip: '203.0.113.9' });
  });
});

test('checkAcl omits an unspecified ip so the server resolves it', async () => {
  let seen = null;
  await withServer(router({
    'POST /api/acl/check': (body) => {
      seen = body;
      return ok({ matched: false });
    },
  }), async (baseUrl) => {
    await clientFor(baseUrl).checkAcl({ path: '/x' });
    assert.deepEqual(seen, { path: '/x' });
  });
});

test('checkRateLimit unwraps the result envelope', async () => {
  await withServer(router({
    'POST /api/ratelimit/check': ok({ allowed: false, decision: 'block', action_taken: 'blocked', retry_after: 12 }),
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).checkRateLimit({ path: '/api/search' });
    assert.equal(out.ok, true);
    assert.equal(out.result.allowed, false);
    assert.equal(out.result.retry_after, 12);
  });
});

test('evaluatePolicy unwraps the result envelope', async () => {
  await withServer(router({
    'POST /api/policies/evaluate': ok({ matched: true, decision: 'block', action_taken: 'blocked', reason: 'rule_block' }),
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).evaluatePolicy({ path: '/checkout' });
    assert.equal(out.result.action_taken, 'blocked');
  });
});

test('evaluateBot forwards method and the end-user headers', async () => {
  let seen = null;
  await withServer(router({
    'POST /api/botguard/evaluate': (body) => {
      seen = body;
      return ok({ suspicious: false, action_taken: 'monitored' });
    },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).evaluateBot({
      path: '/login',
      method: 'post',
      headers: { 'User-Agent': 'curl/8.0' },
    });
    assert.equal(out.result.action_taken, 'monitored');
    assert.equal(seen.method, 'post');
    assert.deepEqual(seen.headers, { 'User-Agent': 'curl/8.0' });
  });
});

test('verifyKey issues a GET and returns the whole payload', async () => {
  let method = null;
  await withServer(router({
    'GET /api/apikey-info': (body, req) => {
      method = req.method;
      return { payload: { valid: true, api_key: { id: 3, key_prefix: 'snt_abcd' }, site: { id: 7, name: 'shop' } } };
    },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).verifyKey();
    assert.equal(method, 'GET');
    assert.equal(out.ok, true);
    assert.equal(out.result.valid, true);
    assert.equal(out.result.site.name, 'shop');
  });
});

// --- failure behaviour -----------------------------------------------------

test('timeout fails OPEN by default', async () => {
  await withServer(slow(150), async (baseUrl) => {
    const out = await clientFor(baseUrl, { timeoutMs: 40 }).checkAcl({ path: '/x' });
    assert.equal(out.ok, false);
    assert.equal(out.error.code, 'timeout');
    assert.equal(out.result.decision, 'allow');
    assert.equal(out.result.action_taken, 'allowed');
    assert.equal(out.result.unavailable, true);
  });
});

test('timeout fails CLOSED when configured', async () => {
  await withServer(slow(150), async (baseUrl) => {
    const out = await clientFor(baseUrl, { timeoutMs: 40, failureMode: 'closed' }).checkAcl({ path: '/x' });
    assert.equal(out.ok, false);
    assert.equal(out.result.decision, 'block');
    assert.equal(out.result.action_taken, 'blocked');
  });
});

test('failureMode "throw" surfaces the SentinelError', async () => {
  await withServer(slow(150), async (baseUrl) => {
    const client = clientFor(baseUrl, { timeoutMs: 40, failureMode: 'throw' });
    await assert.rejects(
      () => client.checkAcl({ path: '/x' }),
      (e) => e instanceof SentinelError && e.code === 'timeout',
    );
  });
});

test('an unreachable service is reported as network_error and fails open', async () => {
  const client = new SentinelClient({
    baseUrl: 'http://sentinel.invalid',
    apiKey: API_KEY,
    fetchImpl: async () => {
      throw new TypeError('fetch failed');
    },
  });
  const out = await client.checkRateLimit({ path: '/x' });
  assert.equal(out.ok, false);
  assert.equal(out.error.code, 'network_error');
  assert.equal(out.result.decision, 'allow');
});

test('HTTP 401 is surfaced as unauthorized', async () => {
  await withServer(router({
    'POST /api/acl/check': { status: 401, payload: { error: 'Invalid or revoked API key' } },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).checkAcl({ path: '/x' });
    assert.equal(out.error.code, 'unauthorized');
    assert.equal(out.error.status, 401);
  });
});

test('a non-JSON body is surfaced as invalid_response', async () => {
  await withServer(router({
    'POST /api/acl/check': { payload: '<html>oops</html>', contentType: 'text/html' },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).checkAcl({ path: '/x' });
    assert.equal(out.error.code, 'invalid_response');
  });
});

test('a 500 response is surfaced as http_error', async () => {
  await withServer(router({
    'POST /api/ratelimit/check': { status: 500, payload: { error: 'boom' } },
  }), async (baseUrl) => {
    const out = await clientFor(baseUrl).checkRateLimit({ path: '/x' });
    assert.equal(out.error.code, 'http_error');
    assert.equal(out.error.status, 500);
  });
});

test('the logger receives a warning when a check degrades', async () => {
  const warnings = [];
  await withServer(slow(150), async (baseUrl) => {
    const client = clientFor(baseUrl, { timeoutMs: 40, logger: { warn: (m) => warnings.push(m) } });
    await client.checkAcl({ path: '/x' });
  });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /failing open/);
});

// --- combined guard --------------------------------------------------------

const HEALTHY = {
  'POST /api/acl/check': ok({ matched: false, action_taken: 'allowed' }),
  'POST /api/ratelimit/check': ok({ allowed: true, action_taken: 'allowed' }),
  'POST /api/policies/evaluate': ok({ matched: false, action_taken: 'allowed' }),
  'POST /api/botguard/evaluate': ok({ suspicious: false, action_taken: 'monitored' }),
};

test('guard requires a client', () => {
  assert.throws(() => createGuard({}), (e) => e.code === 'configuration');
});

test('guard allows a clean request and reports no degradation', async () => {
  const hits = [];
  await withServer(router(HEALTHY, hits), async (baseUrl) => {
    const guard = createGuard({ client: clientFor(baseUrl) });
    const decision = await guard({ path: '/', method: 'GET' });
    assert.equal(decision.allow, true);
    assert.equal(decision.decision, 'allow');
    assert.equal(decision.enforcedBy, null);
    assert.equal(decision.degraded, false);
    assert.deepEqual([...hits].sort(), Object.keys(HEALTHY).sort());
  });
});

test('guard blocks when an ACL rule is enforced', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'block', action_taken: 'blocked', enforced: true }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'acl');
  });
});

test('guard does not block an ACL match that only MONITORED it', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'block', mode: 'monitor', action_taken: 'monitored' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, true);
    assert.equal(decision.enforcedBy, null);
  });
});

test('guard blocks when the rate limit is not allowed', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/ratelimit/check': ok({ allowed: false, decision: 'block', action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/api/x' });
    assert.equal(decision.enforcedBy, 'ratelimit');
  });
});

test('guard blocks when a policy is enforced', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/policies/evaluate': ok({ matched: true, decision: 'block', action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/checkout' });
    assert.equal(decision.enforcedBy, 'policy');
  });
});

test('ACL precedence wins over the rate limit when both would block', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, action_taken: 'blocked' }),
    'POST /api/ratelimit/check': ok({ allowed: false, action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.enforcedBy, 'acl');
  });
});

// --- ACL allow-rule bypass_scopes -----------------------------------------

test('an ACL allow rule neutralises the scope it exempts', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'allow', action_taken: 'allowed', bypass_scopes: ['ratelimit'] }),
    'POST /api/ratelimit/check': ok({ allowed: false, decision: 'block', action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, true);
    assert.equal(decision.enforcedBy, null);
    assert.deepEqual(decision.bypassed, ['ratelimit']);
    // The exempted check still ran, so its verdict is available for auditing.
    assert.equal(decision.checks.ratelimit.result.allowed, false);
  });
});

test('the "policies" scope neutralises the policy check', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'allow', action_taken: 'allowed', bypass_scopes: ['policies'] }),
    'POST /api/policies/evaluate': ok({ matched: true, decision: 'block', action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/checkout' });
    assert.equal(decision.allow, true);
    assert.equal(decision.enforcedBy, null);
    assert.deepEqual(decision.bypassed, ['policy']);
  });
});

test('an ACL allow rule with no scopes bypasses nothing', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'allow', action_taken: 'allowed', bypass_scopes: [] }),
    'POST /api/ratelimit/check': ok({ allowed: false, action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'ratelimit');
    assert.deepEqual(decision.bypassed, []);
  });
});

test('an unknown bypass scope is ignored, not treated as a blanket bypass', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'allow', action_taken: 'allowed', bypass_scopes: ['everything'] }),
    'POST /api/ratelimit/check': ok({ allowed: false, action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'ratelimit');
    assert.deepEqual(decision.bypassed, []);
  });
});

test('an enforced ACL block still wins and carries no bypass', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': ok({ matched: true, list_type: 'block', action_taken: 'blocked' }),
    'POST /api/ratelimit/check': ok({ allowed: false, action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'acl');
    assert.deepEqual(decision.bypassed, []);
  });
});

test('a degraded ACL check never grants a bypass', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': { status: 503, payload: { error: 'unavailable' } },
    'POST /api/ratelimit/check': ok({ allowed: false, action_taken: 'blocked' }),
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/admin' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'ratelimit');
    assert.deepEqual(decision.bypassed, []);
    assert.equal(decision.degraded, true);
  });
});

test('guard keeps allowing traffic when a check degrades, and flags it', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/ratelimit/check': { status: 503, payload: { error: 'unavailable' } },
  }), async (baseUrl) => {
    const decision = await createGuard({ client: clientFor(baseUrl) })({ path: '/x' });
    assert.equal(decision.allow, true);
    assert.equal(decision.degraded, true);
    assert.equal(decision.checks.ratelimit.ok, false);
    assert.equal(decision.checks.acl.ok, true);
  });
});

test('a fail-closed client blocks the request when a check degrades', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': { status: 503, payload: { error: 'unavailable' } },
  }), async (baseUrl) => {
    const guard = createGuard({ client: clientFor(baseUrl, { failureMode: 'closed' }) });
    const decision = await guard({ path: '/x' });
    assert.equal(decision.allow, false);
    assert.equal(decision.enforcedBy, 'acl');
    assert.equal(decision.degraded, true);
  });
});

test('guard supports running a subset of checks', async () => {
  const hits = [];
  await withServer(router(HEALTHY, hits), async (baseUrl) => {
    const guard = createGuard({ client: clientFor(baseUrl), checks: ['ratelimit'] });
    await guard({ path: '/x' });
    assert.deepEqual(hits, ['POST /api/ratelimit/check']);
  });
});

test('guard runs its checks concurrently, not sequentially', async () => {
  await withServer(router({
    ...HEALTHY,
    'POST /api/acl/check': slow(80),
    'POST /api/ratelimit/check': slow(80),
    'POST /api/policies/evaluate': slow(80),
    'POST /api/botguard/evaluate': slow(80),
  }), async (baseUrl) => {
    const guard = createGuard({ client: clientFor(baseUrl, { timeoutMs: 500 }) });
    const started = Date.now();
    await guard({ path: '/x' });
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 250, `expected concurrent execution, took ${elapsed}ms`);
  });
});
