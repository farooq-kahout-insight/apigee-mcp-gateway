/*
 * slack_outcome.js -- turns Slack's {"ok":false} into an HTTP status.
 *
 * Every other backend behind this gateway signals failure with a status code,
 * and everything downstream is built on that: sf-fault-sanitizer keys off the
 * code, audit.js's outcomeFor() maps it to ok/denied/throttled/invalid, the
 * log-based metrics filter on the outcome, and the MCP server's _explain()
 * decides what to tell the model from it. Slack does not play along -- it
 * answers "you are not in that channel" and "your token was revoked" alike with
 * HTTP 200 and {"ok":false,"error":"…"} in the body.
 *
 * Left alone, that produces the worst possible audit record: outcome "ok" on a
 * call that did nothing, and an agent told it succeeded when it did not. So the
 * translation happens here, once, in the proxy's response PostFlow before the
 * redactor and the audit builder run, rather than being approximated in three
 * places afterwards.
 *
 * Runs inside Apigee's Rhino engine (ES5 only) but the pure function is
 * require()-able under Node for unit tests.
 */

/* Slack's error strings, grouped by who has the problem.

   The 5xx group is the one worth arguing about. invalid_auth and token_revoked
   mean the token in the KVM is bad -- the gateway's credential, not the
   caller's. Mapping those to 401 would tell the agent its own API key was
   rejected and send an operator hunting through consumer keys for a fault that
   lives in the KVM. 502 says what is true: the gateway could not authenticate
   to the upstream. */
var DENIED = {
    not_in_channel: 1, channel_not_found: 1, is_archived: 1,
    missing_scope: 1, not_allowed_token_type: 1, no_permission: 1,
    restricted_action: 1, restricted_action_read_only_channel: 1,
    restricted_action_thread_only_channel: 1, restricted_action_non_threadable_channel: 1,
    ekm_access_denied: 1, org_login_required: 1
};
var UPSTREAM_AUTH = {
    invalid_auth: 1, not_authed: 1, token_revoked: 1, token_expired: 1,
    account_inactive: 1, no_permission_bot: 1
};

/* Fixed per class. Slack's own error string is not echoed to the caller:
   "channel_not_found" and "not_in_channel" together tell an agent whether a
   channel it guessed at exists, which is the allowlist enumeration
   RF-Channel-Denied was written to prevent, arriving by another door. The
   string is kept for the audit, where the reader is trusted. */
function classify(slackError) {
    var e = String(slackError || '');
    if (DENIED.hasOwnProperty(e)) {
        return { status: 403, reason: 'Forbidden', error: 'forbidden',
                 message: 'Slack refused this operation for the gateway\'s credential.' };
    }
    if (UPSTREAM_AUTH.hasOwnProperty(e)) {
        return { status: 502, reason: 'Bad Gateway', error: 'upstream_error',
                 message: 'The gateway could not authenticate to Slack. This is a gateway configuration problem, not a problem with your credential.' };
    }
    if (e === 'ratelimited' || e === 'rate_limited') {
        return { status: 429, reason: 'Too Many Requests', error: 'rate_limited',
                 message: 'Slack rate limit reached. Wait before retrying.' };
    }
    if (e === 'fatal_error' || e === 'internal_error' || e === 'service_unavailable') {
        return { status: 502, reason: 'Bad Gateway', error: 'upstream_error',
                 message: 'Slack returned an internal error.' };
    }
    return { status: 400, reason: 'Bad Request', error: 'bad_request',
             message: 'Slack rejected the request.' };
}

/* Returns null when there is nothing to do -- a non-2xx status (already
   meaningful), an unparseable body, or ok:true. Non-2xx is left alone
   deliberately: a 429 from Slack's own rate limiter, or a 5xx, already says
   what it means, and rewriting it from a body that may not even be JSON would
   lose information rather than add it. */
function outcome(status, body) {
    var code = Number(status);
    if (!(code >= 200 && code < 300)) { return null; }
    var parsed;
    try {
        parsed = JSON.parse(body);
    } catch (e) {
        return null;
    }
    if (parsed === null || typeof parsed !== 'object') { return null; }
    if (parsed.ok !== false) { return null; }
    var verdict = classify(parsed.error);
    verdict.slackError = String(parsed.error || 'unknown');
    return verdict;
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var verdict = outcome(context.getVariable('response.status.code'),
                          context.getVariable('response.content') || '');
    if (verdict !== null) {
        /* Recorded before the body is replaced. This is the only place the
           precise Slack error survives, and it is what makes "the bot is not in
           that channel" distinguishable from "the token lost a scope" when
           someone reads the audit six weeks later. */
        context.setVariable('airlock.slack.error', verdict.slackError);
        context.setVariable('response.status.code', verdict.status);
        context.setVariable('response.reason.phrase', verdict.reason);
        context.setVariable('response.header.Content-Type', 'application/json');
        context.setVariable('response.content', JSON.stringify({
            error: verdict.error, message: verdict.message
        }));
    }
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { outcome: outcome, classify: classify };
}
