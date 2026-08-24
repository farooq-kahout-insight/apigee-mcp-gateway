/*
 * Builds the single JSON record the gateway writes to Cloud Logging per request.
 *
 * The record is assembled here rather than templated inside the MessageLogging
 * policy for two reasons. First, escaping: a field like an issue title is
 * agent-supplied text, and a quote in it would silently corrupt a hand-built
 * JSON template, turning a structured audit entry into an unparseable string
 * exactly when someone is trying to hide something. Second, classification:
 * "which tool was called" is a judgement about verb and path that belongs in
 * one tested function instead of being scattered across policy conditions in
 * two proxy bundles.
 *
 * Nothing derived from the response body is logged, and no credential is logged
 * in a usable form: the caller's API key appears only as a fingerprint. The
 * audit answers who did what, to what, and with what outcome -- never what came
 * back. That keeps the "no secrets in logs" property true by construction
 * rather than by relying on the redaction pass having caught everything.
 */

/* An issue title is the only caller-supplied string that reaches the log, and
   only because "which issue did this agent open" is the point of the audit. */
var MAX_DETAIL = 120;

/* Maps verb and path to the tool that was actually invoked. Kept deliberately
   closed: an unrecognised shape is logged as unknown rather than guessed at,
   so a path that slips past the proxy's own allowlist is conspicuous. */
function classify(proxy, verb, path) {
    var p = String(path || '');
    if (proxy === 'weather-v1') {
        if (p.indexOf('/forecast') === 0) { return 'weather.forecast'; }
        if (p.indexOf('/archive') === 0) { return 'weather.archive'; }
        if (p.indexOf('/selftest') === 0) { return 'weather.selftest'; }
    }
    if (proxy === 'github-v1') {
        if (/^\/repos\/[^\/]+\/[^\/]+\/issues\/?$/.test(p)) {
            return verb === 'POST' ? 'github.issues.create' : 'github.issues.list';
        }
    }
    if (proxy === 'llm-v1') {
        if (p.indexOf('/chat/completions') === 0 && verb === 'POST') { return 'llm.chat'; }
        if (p.indexOf('/models') === 0 && verb === 'GET') { return 'llm.models'; }
    }
    return (proxy || 'unknown') + '.unknown';
}

/* Outcome is a coarse verdict, not a status code restatement: it is what a
   log-based metric or an alert filter should key on, and it must stay stable
   even if a policy's chosen status code is tuned later. */
function outcomeFor(status, faultName) {
    var code = Number(status);
    if (code >= 200 && code < 300) { return 'ok'; }
    if (code === 401) { return 'unauthenticated'; }
    if (code === 403) { return 'denied'; }
    if (code === 429) { return 'throttled'; }
    if (code >= 400 && code < 500) { return 'invalid'; }
    if (code >= 500) { return 'error'; }
    return faultName ? 'error' : 'unknown';
}

function num(value) {
    var n = Number(value);
    return (value === null || value === undefined || value === '' || isNaN(n)) ? null : n;
}

function span(start, end) {
    var a = num(start), b = num(end);
    return (a === null || b === null || b < a) ? null : b - a;
}

function truncate(text) {
    var s = String(text === null || text === undefined ? '' : text);
    return s.length > MAX_DETAIL ? s.substring(0, MAX_DETAIL) : s;
}

/* Drops keys with no value so a reader can tell "not applicable" from "empty",
   and so the github-only fields do not appear as nulls on every weather call. */
function compact(obj) {
    var out = {}, k;
    for (k in obj) {
        if (obj.hasOwnProperty(k) && obj[k] !== null && obj[k] !== undefined && obj[k] !== '') {
            out[k] = obj[k];
        }
    }
    return out;
}

/* The consumer key is a live credential: presenting it in x-api-key is how an
   agent authenticates, so a key sitting in an audit record makes read access to
   the log equivalent to holding the key. An earlier version of this file logged
   Apigee's client_id verbatim and did exactly that. What the audit actually
   needs is a handle, not the secret: "these forty records came from one caller",
   and "this record is the one matching the key in my hand". A short fingerprint
   answers both. FNV-1a is not a cryptographic hash and nothing here pretends it
   is; the only property leaned on is that eight hex digits do not give a log
   reader back a 48-character key, while an investigator who already holds a key
   can fingerprint it and grep. */
function fingerprint(value) {
    var s = String(value || ''), h = 2166136261, i;
    if (!s) { return null; }
    for (i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        /* The FNV prime by shift-and-add. A plain h * 16777619 would be done in
           double precision and quietly lose the low bits. */
        h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
        h = h >>> 0;
    }
    var hex = h.toString(16);
    while (hex.length < 8) { hex = '0' + hex; }
    return hex;
}

/* X-Forwarded-For, and why the raw header is not good enough.
   The gateway sits behind a Google external ALB, so the caller's address only
   reaches Apigee inside this header -- client.ip is the load balancer. The
   header arrives as a chain, and which element is which is not something to
   assume: an earlier version recorded the plain header value and produced
   records naming 35.191.34.3, a Google front end, as the "client" on every
   served request while refusals correctly showed the real caller. A field that
   is right only on the requests nobody is investigating is worse than absent.

   So the chain is parsed and kept. By the X-Forwarded-For convention the first
   element is the originating client -- but it is also the one element a caller
   can write themselves, since the ALB appends rather than replaces. It is a
   claim, and client_ip records it as one; forwarded_for keeps the whole chain
   so that an investigator can see the hops Google actually added and judge the
   claim against them. Accepts both representations Apigee can hand back: a
   single comma-joined header value, or the bracketed list that .values gives
   when the header arrives more than once. */
function forwardedChain(raw) {
    var s = String(raw == null ? '' : raw), parts, out = [], i, part;
    s = s.replace(/^\s*\[/, '').replace(/\]\s*$/, '');
    parts = s.split(',');
    for (i = 0; i < parts.length; i++) {
        part = parts[i].replace(/["'\s]/g, '');
        if (part) { out.push(part); }
    }
    return out;
}

/* The caller's chain, from wherever it still survives. */
function callerChain(g) {
    return forwardedChain(g('airlock.xff') || g('airlock.xff_last')
                          || g('request.header.x-forwarded-for.values')
                          || g('request.header.x-forwarded-for'));
}

/* The agent's name, from wherever it still survives.

   The first two are what Apigee publishes when VerifyAPIKey completes. Neither
   exists when it refuses at the API Product scope -- it raises the fault from
   inside itself and publishes nothing -- so airlock.app_name, which AE-Resolve-App
   fills by looking the app up from the key directly, is what attributes precisely
   the records worth reading: an identified agent reaching past its scope. Empty
   means the key resolved to no app at all, and buildRecord is right to call that
   caller unauthenticated. */
function callerName(g) {
    return g('developer.app.name') || g('verifyapikey.VA-VerifyAPIKey.app.name')
           || g('airlock.app_name') || '';
}

function buildRecord(v) {
    v = v || {};
    var action = classify(v.proxy, v.verb, v.path);
    var record = {
        ts: v.ts || null,
        agent: v.app || 'unauthenticated',
        client_key_fp: fingerprint(v.clientId),
        proxy: v.proxy || null,
        revision: v.revision || null,
        verb: v.verb || null,
        path: v.path || null,
        action: action,
        status: num(v.status),
        outcome: outcomeFor(v.status, v.faultName),
        fault: v.faultName || null,
        latency_ms: span(v.requestStart, v.responseEnd),
        target_latency_ms: span(v.targetStart, v.targetEnd),
        target_host: v.targetHost || null,
        message_id: v.messageId || null,
        client_ip: v.clientIp || null,
        /* Only when there is a chain to show. One hop is the whole story and
           repeating it as a chain adds nothing but bytes to every record. */
        forwarded_for: (v.forwardedFor || []).length > 1
                       ? v.forwardedFor.join(', ') : null
    };
    /* The spec's "log the service that was called" for a write: for GitHub that
       is the repository and the issue that was opened, which is the part a human
       reviewing an incident actually needs. */
    if (action.indexOf('github.') === 0) {
        record.repo = v.repo || null;
        if (action === 'github.issues.create') {
            record.detail = truncate(v.issueTitle) || null;
        }
    }
    /* Model spend, and nothing else about the exchange. There is deliberately no
       field here for the prompt or the completion: the counters answer "who spent
       what, where", which is what a budget alert and an incident review both need,
       and neither of them needs the text. Adding it later would also quietly
       change what read access to the log is worth, since a prompt is often the
       most sensitive thing an agent handles.

       The model recorded is the one the upstream says it served, falling back to
       the one the caller asked for. The fallback is what makes a refusal legible:
       a denied request never reaches the upstream, so the requested model is the
       only name in existence, and it is exactly the name an operator wants when
       reading why the call was refused. When the two disagree on a served call
       both are kept -- being quietly answered by a different model than the one
       asked for is a fact an audit exists to surface, not to smooth over. */
    if (action.indexOf('llm.') === 0) {
        record.model = v.model || v.requestedModel || null;
        if (v.model && v.requestedModel && v.model !== v.requestedModel) {
            record.requested_model = v.requestedModel;
        }
        record.tokens_prompt = num(v.promptTokens);
        record.tokens_completion = num(v.completionTokens);
        record.tokens_total = num(v.totalTokens);
    }
    return compact(record);
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var g = function (name) { return context.getVariable(name); };
    var record = buildRecord({
        ts: g('system.time.iso8601') || new Date().toISOString(),
        app: callerName(g),
        /* Fingerprinted, never stored. The last fallback is the raw header so
           that even a wholly unauthenticated caller is correlatable across
           records -- a repeated bad key is the shape of someone guessing. */
        clientId: g('client_id') || g('verifyapikey.VA-VerifyAPIKey.client_id')
                  || g('request.header.x-api-key'),
        proxy: g('apiproxy.name'),
        revision: g('apiproxy.revision'),
        verb: g('request.verb'),
        path: g('proxy.pathsuffix'),
        status: g('response.status.code') || g('message.status.code'),
        faultName: g('fault.name'),
        requestStart: g('client.received.start.timestamp'),
        responseEnd: g('system.timestamp'),
        targetStart: g('target.sent.start.timestamp'),
        targetEnd: g('target.received.end.timestamp'),
        targetHost: g('target.host'),
        messageId: g('messageid'),
        /* airlock.xff is the snapshot AM-Capture-Caller took at the very top
           of the request, and it has to be: this builder runs in the response
           flow for a served request, and by then the header describes Apigee's
           own call to the target rather than the client's call to Apigee. The
           direct reads stay as a fallback for any path that faults before the
           inbound shared flow, where the live header is still the client's.
           .values before the plain accessor throughout, because when a header
           arrives more than once Apigee hands back only the last occurrence,
           which is the nearest proxy: exactly the wrong end of the chain. */
        forwardedFor: callerChain(g),
        clientIp: callerChain(g)[0] || g('client.ip'),
        repo: g('gh.repo_full'),
        issueTitle: g('airlock.issue.title'),
        /* All four are set by EV-LLM-Usage, which only runs on a 200 from the
           upstream, so on every other outcome they resolve to null and compact()
           drops them. llm.requested_model comes from the guard instead and
           survives a refusal, which is the point of reading both. */
        model: g('llm.model'),
        requestedModel: g('llm.requested_model'),
        promptTokens: g('llm.usage.prompt_tokens'),
        completionTokens: g('llm.usage.completion_tokens'),
        totalTokens: g('llm.usage.total_tokens')
    });
    context.setVariable('airlock.audit.record', JSON.stringify(record));
    context.setVariable('airlock.audit.action', record.action);
    context.setVariable('airlock.audit.outcome', record.outcome);
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        buildRecord: buildRecord,
        classify: classify,
        outcomeFor: outcomeFor,
        fingerprint: fingerprint,
        forwardedChain: forwardedChain,
        callerChain: callerChain,
        callerName: callerName,
        MAX_DETAIL: MAX_DETAIL
    };
}
