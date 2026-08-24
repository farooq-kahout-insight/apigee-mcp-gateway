/*
 * llm_guard.js -- rebuilds an outbound OpenAI-compatible chat-completions
 * payload before it is spent against the gateway's OpenRouter credential.
 *
 * Runs inside Apigee's Rhino engine (ES5 only); the pure function is
 * require()-able under Node for unit tests, same arrangement as
 * github_issue.js and redact.js.
 *
 * The controls here all answer the same question: the caller holds a consumer
 * key, not a model-provider key, so what may it decide? It may decide the
 * conversation. It may not decide which model it spends the gateway's money
 * on, how much of it, how the response is transported, or which upstream
 * provider serves it.
 *
 * Unlike github_issue.js this is NOT a field allowlist: a chat body legitimately
 * carries tools, response_format, seed, and vendor extensions this gateway has
 * no opinion about, and dropping them would break real clients. It is a
 * denylist of the four routing fields plus a clamp, which is a weaker stance
 * and a deliberate one.
 */

var DEFAULT_MAX_TOKENS = 1024;

/* Fields that let a caller re-route or re-price the request. The gateway
 * decides routing policy, not the caller:
 *   provider    pins or excludes upstream providers, and can select a more
 *               expensive one than the allowlist implies
 *   models      the fallback-array form -- a second, unscreened model list that
 *               would bypass the allowlist entirely when the first model errors
 *   route       "fallback" routing, same bypass by another name
 *   transforms  server-side prompt rewriting; changes what was actually sent
 *               and so makes the audit record a lie
 */
var ROUTING_FIELDS = ['provider', 'transforms', 'models', 'route'];

function parseAllowed(csv) {
    if (typeof csv !== 'string') { return []; }
    var out = [];
    var parts = csv.split(',');
    for (var i = 0; i < parts.length; i++) {
        var p = parts[i].replace(/^\s+|\s+$/g, '');
        if (p !== '') { out.push(p); }
    }
    return out;
}

function parseCap(raw) {
    var n = parseInt(raw, 10);
    // Fails open to a default, unlike the allowlist, because the blast radius
    // of a missing ceiling is cost -- not access to a model nobody approved.
    if (isNaN(n) || n <= 0) { return DEFAULT_MAX_TOKENS; }
    return n;
}

function guard(raw, allowedCsv, capRaw) {
    var parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (e) {
        return { error: 'unparseable' };
    }
    if (parsed === null || typeof parsed !== 'object' ||
        Object.prototype.toString.call(parsed) === '[object Array]') {
        return { error: 'not_an_object' };
    }

    // Apigee cannot run response policies over an SSE stream, so a streamed
    // completion would silently disable outbound redaction, usage extraction,
    // and the status and latency fields of the audit record. Refusing is the
    // honest option: the alternative is a response path that looks armed and
    // is not. Supporting streaming means giving those three controls a
    // streaming implementation, which is its own milestone, not a flag.
    // Every refusal from here down carries the model that was asked for, and
    // that is an audit requirement rather than a courtesy. A denial record that
    // says only "somebody was refused something" is not a finding anyone can
    // act on: the whole reason to alert on refused model requests is to see
    // which model an agent kept reaching for. The value is caller-supplied
    // text, so it is length-bounded where it enters the flow, below.
    var asked = (typeof parsed.model === 'string') ? parsed.model : '';

    if (parsed.stream === true) {
        return { error: 'stream_unsupported', model: asked };
    }

    if (asked === '') {
        return { error: 'missing_model' };
    }

    // Fail closed: an unset or empty allowlist denies every model rather than
    // permitting every model. Same stance as the github repo allowlist -- a
    // gateway that has not been told what it may do may do nothing.
    var allowed = parseAllowed(allowedCsv);
    var ok = false;
    for (var i = 0; i < allowed.length; i++) {
        if (allowed[i] === parsed.model) { ok = true; break; }
    }
    if (!ok) { return { error: 'model_denied', model: asked }; }

    var cap = parseCap(capRaw);
    var requested = parseInt(parsed.max_tokens, 10);
    // Inserted when the caller omitted it, so an unbounded request cannot be
    // made by simply leaving the field out.
    parsed.max_tokens = (isNaN(requested) || requested <= 0 || requested > cap) ? cap : requested;

    for (var j = 0; j < ROUTING_FIELDS.length; j++) {
        delete parsed[ROUTING_FIELDS[j]];
    }

    return { json: JSON.stringify(parsed), model: parsed.model, max_tokens: parsed.max_tokens };
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var result = guard(
        context.getVariable('request.content') || '',
        context.getVariable('llm.allowed_models'),
        context.getVariable('llm.max_tokens_cap')
    );
    if (result.error) {
        context.setVariable('llm.guard.error', result.error);
        // Set on the refusal path too, so the audit's denied record can name the
        // model. Truncated because this string never passed the allowlist -- it
        // is whatever the caller sent, and an audit log is a poor place to store
        // an unbounded field somebody else chose.
        if (result.model) {
            context.setVariable('llm.requested_model', String(result.model).substring(0, 120));
        }
    } else {
        context.setVariable('request.content', result.json);
        context.setVariable('request.header.Content-Type', 'application/json');
        // Handed to the audit, which runs long after the body is gone. The
        // model and the ceiling are recorded; the messages never are. The audit
        // answers "who spent what, where", not "what was said".
        context.setVariable('llm.requested_model', result.model);
        context.setVariable('llm.effective_max_tokens', result.max_tokens);
    }
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        guard: guard,
        parseAllowed: parseAllowed,
        parseCap: parseCap,
        ROUTING_FIELDS: ROUTING_FIELDS,
        DEFAULT_MAX_TOKENS: DEFAULT_MAX_TOKENS
    };
}
