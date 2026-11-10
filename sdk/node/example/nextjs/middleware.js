/**
 * Sentinel AI guard, applied to every request by Next.js middleware.
 *
 * Runs on the Edge runtime, where the global `fetch` the SDK relies on is
 * available. The client is created once at module scope so the API key and
 * configuration are validated at boot, not per request.
 *
 * Environment:
 *   SENTINEL_BASE_URL  origin of your SENTINEL-AI deployment (defaults to a
 *                      local dev server on http://127.0.0.1:5000)
 *   SENTINEL_API_KEY   per-site key issued in the dashboard (snt_...), required
 */
import { NextResponse } from 'next/server';
import { SentinelClient, createGuard } from 'sentinel-ai-sdk';

const client = new SentinelClient({
  baseUrl: process.env.SENTINEL_BASE_URL ?? 'http://127.0.0.1:5000',
  apiKey: process.env.SENTINEL_API_KEY ?? '',
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
    return new NextResponse('Blocked by Sentinel AI', {
      status: 403,
      headers: { 'x-sentinel-enforced-by': decision.enforcedBy ?? 'unknown' },
    });
  }

  const response = NextResponse.next();
  response.headers.set('x-sentinel-decision', decision.decision);
  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
