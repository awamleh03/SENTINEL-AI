/**
 * Framework-agnostic request guard: runs the configured Sentinel checks for
 * one incoming request and folds them into a single decision.
 *
 * Only verdicts the server actually ENFORCED are treated as blocking, so a
 * rule running in `monitor` mode never blocks traffic here:
 *   - ACL       blocks when result.action_taken === 'blocked'
 *   - rate limit blocks when result.allowed === false
 *   - policy    blocks when result.action_taken === 'blocked'
 *   - botguard  is monitor-only and never blocks
 *
 * Precedence is ACL -> rate limit -> policy; the first enforced block wins.
 * Checks run in parallel (one round trip, not four).
 *
 * An ACL `allow` rule may also exempt named protection scopes (its
 * `bypass_scopes`); those scopes are then neutralised for this request. See
 * SCOPE_TO_CHECK below.
 */

import { SentinelError } from './client.js';

export const ALL_CHECKS = ['acl', 'ratelimit', 'policy', 'bot'];

/**
 * ACL allow-rule exemption scopes -> the guard check each one neutralises.
 * The server's scope vocabulary (ACL_SCOPES in modules/database.py) is
 * `policies | ratelimit | botguard`; here they map onto the guard's check
 * names. A scope with no entry is ignored rather than silently over-bypassing.
 */
const SCOPE_TO_CHECK = {
  policies: 'policy',
  ratelimit: 'ratelimit',
  botguard: 'bot',
};

export function createGuard({ client, checks = ALL_CHECKS } = {}) {
  if (!client || typeof client.checkAcl !== 'function') {
    throw new SentinelError('configuration', 'createGuard requires a SentinelClient instance');
  }
  const selected = checks.filter((name) => ALL_CHECKS.includes(name));

  /**
   * @param {object} request
   * @param {string} [request.path]    Request path evaluated by ACL / rate limit / policies.
   * @param {string} [request.method]  HTTP method, used by the bot heuristic.
   * @param {object} [request.headers] End-user headers, used by the bot heuristic.
   * @param {string} [request.ip]      Overrides the IP for ACL evaluation.
   */
  return async function guard(request = {}) {
    const { path, method = 'GET', headers = {}, ip } = request;

    const tasks = {};
    if (selected.includes('acl')) tasks.acl = client.checkAcl({ path, ip });
    if (selected.includes('ratelimit')) tasks.ratelimit = client.checkRateLimit({ path });
    if (selected.includes('policy')) tasks.policy = client.evaluatePolicy({ path });
    if (selected.includes('bot')) tasks.bot = client.evaluateBot({ path, method, headers });

    const names = Object.keys(tasks);
    const settled = await Promise.all(names.map((name) => tasks[name]));

    const outcomes = {};
    names.forEach((name, index) => {
      outcomes[name] = settled[index];
    });

    // An ACL `allow` rule exempts the scopes it explicitly lists. Only a real
    // allow verdict carries them: a degraded (fail-open/closed) ACL check has
    // no `bypass_scopes`, so it never grants an exemption.
    const bypassed = new Set();
    if (outcomes.acl && outcomes.acl.ok && outcomes.acl.result.list_type === 'allow') {
      for (const scope of outcomes.acl.result.bypass_scopes || []) {
        const check = SCOPE_TO_CHECK[scope];
        if (check && selected.includes(check)) {
          bypassed.add(check);
        }
      }
    }

    let enforcedBy = null;
    if (outcomes.acl && outcomes.acl.result.action_taken === 'blocked') {
      enforcedBy = 'acl';
    } else if (!bypassed.has('ratelimit') && outcomes.ratelimit && outcomes.ratelimit.result.allowed === false) {
      enforcedBy = 'ratelimit';
    } else if (!bypassed.has('policy') && outcomes.policy && outcomes.policy.result.action_taken === 'blocked') {
      enforcedBy = 'policy';
    }

    return {
      allow: enforcedBy === null,
      decision: enforcedBy === null ? 'allow' : 'block',
      enforcedBy,
      // Check names exempted by a matching ACL allow rule (empty when none).
      bypassed: [...bypassed],
      // True when at least one check could not be completed (failed open/closed).
      degraded: names.some((name) => outcomes[name].ok === false),
      checks: outcomes,
      path: path ?? null,
    };
  };
}
