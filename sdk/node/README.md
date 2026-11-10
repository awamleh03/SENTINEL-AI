# Sentinel AI SDK (Node.js / Next.js)

Inline request-guard SDK for the SENTINEL-AI API. It calls the existing
server-side checks — access lists, rate limits, policies and bot scoring — and
folds them into one decision your middleware can act on.

> **Local package, not published.** The `name` in `package.json`
> (`sentinel-ai-sdk`) is a **placeholder**: the availability of any npm name has
> **not** been verified and nothing is published. The package is marked
> `"private": true` so an accidental `npm publish` is refused. It also has
> **zero runtime dependencies**, so no dependency names are assumed either.

## Requirements

Node.js 18+ (uses the global `fetch`). No build step, no `npm install` needed.

## Install locally

```bash
# from a consuming app, referencing this folder
npm install /absolute/path/to/SENTINEL-AI/sdk/node
```

## Quick start

```js
import { SentinelClient, createGuard } from 'sentinel-ai-sdk';

const client = new SentinelClient({
  baseUrl: 'https://sentinel.example.com',
  apiKey: process.env.SENTINEL_API_KEY, // snt_... issued per site in the dashboard
  timeoutMs: 800,
});

const guard = createGuard({ client });

const decision = await guard({
  path: '/checkout',
  method: 'POST',
  headers: { 'User-Agent': req.headers.get('user-agent') },
});

if (!decision.allow) {
  // decision.enforcedBy is 'acl' | 'ratelimit' | 'policy'
}
```

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `baseUrl` | — (required) | Origin of your SENTINEL-AI deployment. Trailing slashes are stripped. |
| `apiKey` | — (required) | Site API key, sent as the `X-API-Key` header. Never logged. |
| `timeoutMs` | `1000` | Per-request budget. Keep it well below your own request budget. |
| `failureMode` | `'open'` | Behaviour when the service cannot be reached — see below. |
| `logger` | `null` | Optional object with a `warn(message)` method, called on degraded checks. |
| `fetchImpl` | global `fetch` | Override for tests or custom runtimes. |

Invalid configuration throws a `SentinelError` with `code: 'configuration'` at
construction time (fail fast, not on the request path).

## Timeout and failure behaviour

Every request is bounded by `timeoutMs` through an `AbortController`. Failure
modes are explicit and never silent:

| `failureMode` | `result.decision` | `result.action_taken` | Envelope |
| --- | --- | --- | --- |
| `'open'` (default) | `allow` | `allowed` | `ok: false`, `error.code` set |
| `'closed'` | `block` | `blocked` | `ok: false`, `error.code` set |
| `'throw'` | — | — | the `SentinelError` is re-thrown |

The default is fail-**open**: the dashboard's rules are all monitor-by-default,
and a guard that fails closed on a network blip would take your site down with
the security service. Choose `'closed'` only for endpoints where availability is
genuinely less important than blocking.

`error.code` is one of `configuration`, `timeout`, `network_error`,
`unauthorized`, `http_error`, `invalid_response`. When a call degrades, the
fallback result carries `reason: 'sentinel_unavailable'` and `unavailable: true`,
and the client emits one `logger.warn` line.

## Return envelope

Every method resolves — it never throws unless `failureMode` is `'throw'`:

```js
{ ok: true,  result: { /* the server's result object */ }, raw: { /* full payload */ } }
{ ok: false, error: { code, message, status }, result: { /* fallback verdict */ } }
```

`result` mirrors the server payload exactly, so `decision` (the detection
verdict) and `action_taken` (what was actually enforced) stay distinct. A rule
in `monitor` mode reports `decision: 'block'` with `action_taken: 'monitored'`.

## Methods

| Method | Endpoint | Body sent |
| --- | --- | --- |
| `checkAcl({ path, ip })` | `POST /api/acl/check` | `path`, `ip` (omit `ip` to use the caller IP) |
| `checkRateLimit({ path })` | `POST /api/ratelimit/check` | `path` |
| `evaluatePolicy({ path })` | `POST /api/policies/evaluate` | `path` |
| `evaluateBot({ path, method, headers })` | `POST /api/botguard/evaluate` | `path`, `method`, `headers` |
| `verifyKey()` | `GET /api/apikey-info` | — |

`evaluateBot` forwards the **end user's** header values (`User-Agent`,
`Accept-Language`, `Accept`, `Referer`); the server prefers them over the
headers of the SDK request itself.

## Combined guard

`createGuard({ client, checks })` returns `async (request) => decision`.
`checks` defaults to `['acl', 'ratelimit', 'policy', 'bot']`.

The checks run **in parallel** (one round trip, not four). Only verdicts the
server actually enforced can block:

| Check | Blocks when |
| --- | --- |
| `acl` | `result.action_taken === 'blocked'` |
| `ratelimit` | `result.allowed === false` |
| `policy` | `result.action_taken === 'blocked'` |
| `bot` | never — bot scoring is monitor-only |

Precedence is ACL → rate limit → policy; the first enforced block wins.

### ACL allow rules and `bypass_scopes`

An ACL **allow** rule may exempt specific protection scopes, listed on the rule
as `scope` (server value) and returned by `/api/acl/check` as `bypass_scopes`.
The guard honours them: a block from an exempted scope is not enforced for that
request.

| `bypass_scopes` entry | Guard check neutralised |
| --- | --- |
| `ratelimit` | `ratelimit` |
| `policies` | `policy` |
| `botguard` | `bot` (already monitor-only, so no visible effect) |

Precise scope of the bypass:

- Only a returned **allow** verdict carries `bypass_scopes`. An ACL **block**
  rule always wins (the server evaluates denies first), and a degraded ACL check
  (fail-open/closed) has no `bypass_scopes`, so it **never** grants an exemption.
- An allow rule with an empty `scope` exempts **nothing** — it is by no means a
  blanket bypass.
- Only the exempted checks are neutralised; every other check still applies, and
  an enforced ACL block still wins over everything.
- The exempted checks are still **called** (the four run in one round trip), so
  their verdicts remain in `checks` for auditing — they simply cannot block.

```js
{
  allow: boolean,          // false only when something was enforced
  decision: 'allow' | 'block',
  enforcedBy: 'acl' | 'ratelimit' | 'policy' | null,
  bypassed: string[],      // checks exempted by an ACL allow rule ([] when none)
  degraded: boolean,       // at least one check could not be completed
  checks: { acl, ratelimit, policy, bot },  // raw envelopes, for auditing
  path
}
```

Note that the guard itself consumes the rate-limit budget, because the rate
limit is evaluated on your behalf on every call.

## Next.js middleware example

A complete, runnable example lives in [`example/nextjs`](./example/nextjs)
(Next.js 15 App Router). Middleware runs on the Edge runtime, where the global
`fetch` is available; create the client once at module scope.

```js
// middleware.js
import { NextResponse } from 'next/server';
import { SentinelClient, createGuard } from 'sentinel-ai-sdk';

const client = new SentinelClient({
  baseUrl: process.env.SENTINEL_BASE_URL,
  apiKey: process.env.SENTINEL_API_KEY,
  timeoutMs: 800,
});

const guard = createGuard({ client });

export async function middleware(request) {
  const decision = await guard({
    path: request.nextUrl.pathname,
    method: request.method,
    headers: {
      'User-Agent': request.headers.get('user-agent') ?? '',
      Accept: request.headers.get('accept') ?? '',
      'Accept-Language': request.headers.get('accept-language') ?? '',
      Referer: request.headers.get('referer') ?? '',
    },
  });

  if (!decision.allow) {
    return new NextResponse('Blocked', { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
```

This example has been run for real against a local SENTINEL-AI server. With an
enforcing ACL `block` rule on `/blocked`, `GET /` returned `200` (header
`x-sentinel-decision: allow`) while `GET /blocked` returned `403` (header
`x-sentinel-enforced-by: acl`). To run it yourself:

```bash
cd example/nextjs
npm install
SENTINEL_BASE_URL=http://127.0.0.1:5000 SENTINEL_API_KEY=snt_... npm run dev
```

## Security notes

- Use this only server-side (Node, Edge middleware, a backend route). Never ship
  an API key to the browser.
- The key is sent only as the `X-API-Key` header, matching exactly how the
  server validates it.
- The SDK never logs the key. `logger.warn` output contains the error code and
  message only.
- Keys are managed per site in the dashboard and can be revoked or rotated at
  any time; a revoked key surfaces as `error.code === 'unauthorized'`.

## Tests

```bash
cd sdk/node
npm test
```

The suite uses `node:test` and a throwaway local HTTP server — no network, no
dependencies.
