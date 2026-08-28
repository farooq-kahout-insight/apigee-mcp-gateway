/*
 * redact.js -- response scrubber for the agent-airlock gateway.
 *
 * Runs inside Apigee's Rhino engine (ES5 only: no let/const, no arrow functions)
 * but is written so the pure functions can be require()'d by Node for unit tests.
 *
 * Rules:
 *   (a) replace the value of any object key matching token|secret|password|
 *       api_key|authorization with a marker
 *   (b) scan every string *value* for credential-shaped text and mask it
 *   (c) mask email addresses -> first char + ***@domain
 *   (d) optional, off by default: mask other PII (SSN, payment card, phone)
 *
 * Rule (b) is the one that earns its keep on a read path. Rule (a) keys on the
 * field *name*, and a backend that returns a secret under a name like "token"
 * is not the threat here: GitHub returns no such field. The secret an agent
 * actually reads back arrives inside `body` or `title` -- ordinary string
 * fields holding whatever a human pasted into an issue -- where a name-based
 * rule never looks.
 *
 * Matches are replaced with a visible marker rather than deleted. A silently
 * removed field is indistinguishable from a field that was never there, which
 * leaves the model free to invent a plausible value for it; a marker tells the
 * model that something was withheld, and tells whoever reads the audit that
 * this response had a secret in it.
 */

var REDACTED = '[redacted]';

var SENSITIVE_KEY = /(^|[_\-.])?(authorization|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|token|secret|client[_\-]?secret|password|passwd|credential)([_\-.]|$)/i;
var EMAIL = /([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})/g;
var MAX_DEPTH = 20;

/* Count of matches in the most recent scrub. The Apigee glue puts it on a
   context variable so the audit record can carry "this response had N secrets
   taken out of it" without carrying the secrets. Module-level state is safe
   here: Apigee runs one JavaScript step against one message at a time. */
var HITS = 0;

/* ------------------------------------------------------------------ helpers */

function luhn(digits) {
    var sum = 0, alt = false, i, d;
    for (i = digits.length - 1; i >= 0; i--) {
        d = Number(digits.charAt(i));
        if (alt) { d = d * 2; if (d > 9) { d -= 9; } }
        sum += d;
        alt = !alt;
    }
    return digits.length > 0 && sum % 10 === 0;
}

/* --------------------------------------------------------- value-level rules
 *
 * Applied in order, because the earlier patterns are the more specific ones: a
 * credentialed URL has to be masked as a URL before the generic vendor-token
 * scan gets a chance to mask only the token inside it and leave the rest.
 *
 * Every rule is used through String.replace. None uses RegExp.test on a /g
 * pattern -- that carries lastIndex between calls and would skip every other
 * match, which is the kind of bug a redactor cannot afford to have.
 */

/* Whole private-key blocks, not just the header line. */
var PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

/* scheme://user:secret@host -- how a PAT leaks in a pasted git remote, and how
   a database password leaks in a pasted connection string. The host survives:
   it is the half that makes a bug report actionable and it is not the secret. */
var CRED_URL = /\b([a-z][a-z0-9+.\-]*):\/\/[^\s:@\/]+:[^\s@\/]+@/gi;

/* A Slack incoming webhook is a bare capability -- no credential accompanies
   it, so the URL is the secret. */
var SLACK_HOOK = /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_\-]+/g;

/* Vendor-prefixed tokens. Longest prefixes first: JS alternation is
   leftmost-first, so sk-or-v1- has to precede sk- or it would never match. */
var VENDOR_TOKEN = new RegExp(
    '(' +
    'github_pat_[A-Za-z0-9_]{20,}' +
    '|gh[pousr]_[A-Za-z0-9]{20,}' +
    '|xox[baprse]-[A-Za-z0-9\\-]{10,}' +
    '|xapp-[0-9]-[A-Za-z0-9\\-]{10,}' +
    '|sk-or-v1-[A-Za-z0-9]{20,}' +
    '|sk-proj-[A-Za-z0-9_\\-]{20,}' +
    '|sk-[A-Za-z0-9]{20,}' +
    '|glpat-[A-Za-z0-9_\\-]{20,}' +
    '|npm_[A-Za-z0-9]{36}' +
    '|pypi-[A-Za-z0-9_\\-]{16,}' +
    '|(?:AKIA|ASIA)[0-9A-Z]{16}' +
    '|AIza[0-9A-Za-z_\\-]{35}' +
    '|ya29\\.[0-9A-Za-z_\\-]{20,}' +
    ')', 'g');

/* Three base64url segments. The eyJ anchor is '{"' encoded, so this fires on a
   JWT-shaped string and not on any long dotted identifier. */
var JWT = /\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}/g;

/* An Authorization header quoted inside an issue -- the shape of every pasted
   failing curl command. The scheme is kept and the credential is not. */
var AUTH_HEADER = /\b(authorization)(\s*:\s*)(bearer|basic|token|digest)?[ \t]*([^\s"',]+)/gi;

/* Labelled key-values in free text: password: x, API_KEY=abc, "secret":"y".
   The separator is [:=] only. The prose form ("the password is hunter2") is
   deliberately not matched: on the llm-v1 path the response body *is* natural
   language, and a rule that fires on the word "is" would redact the model's
   own sentences several times per answer. The cost of that choice is one
   uncaught phrasing; the cost of the alternative is a gateway whose output
   nobody can read.

   The ["']? after the key is not decoration: it is what lets the rule fire on
   the JSON-as-text form "client_secret":"x", where the closing quote sits
   between the key and the colon. Without it the rule silently covers only the
   unquoted shell form, which is the half that leaks least often. */
var LABELLED = /\b(client[_\-]?secret|pass(?:word|wd)|pwd|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|private[_\-]?key|secret|token|credential)s?["']?(\s*[:=]\s*)(["']?)([^\s"',;\]}]{3,})\3/gi;

/* Rule (d), opt-in. Off by default because every one of these also fires on
   ordinary text -- an issue quoting a build number, a version string shaped
   like a phone number -- and a redactor that mangles normal reads is a
   redactor somebody turns off. */
var SSN = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g;
var CARD = /\b(?:[0-9][ \-]?){13,19}\b/g;
var PHONE = /\+[0-9]{1,3}[ \-]?(?:\([0-9]{1,4}\)[ \-]?)?[0-9][0-9 \-]{6,12}[0-9]\b/g;

function hit(replacement) {
    HITS++;
    return replacement;
}

function maskEmails(s) {
    return s.replace(EMAIL, function (_m, first, domain) {
        return first + '***@' + domain;
    });
}

/*
 * The value scanner. Exported on its own so a non-JSON body can be run through
 * it without a parse, and so the tests can address one rule at a time.
 */
function redactText(s, opts) {
    if (typeof s !== 'string' || s === '') { return s; }
    opts = opts || {};

    s = s.replace(PEM, function () { return hit(REDACTED); });
    s = s.replace(CRED_URL, function (_m, scheme) { return hit(scheme + '://' + REDACTED + '@'); });
    s = s.replace(SLACK_HOOK, function () { return hit(REDACTED); });
    s = s.replace(VENDOR_TOKEN, function () { return hit(REDACTED); });
    s = s.replace(JWT, function () { return hit(REDACTED); });
    s = s.replace(AUTH_HEADER, function (_m, key, sep, scheme) {
        return hit(key + sep + (scheme ? scheme + ' ' : '') + REDACTED);
    });
    s = s.replace(LABELLED, function (_m, key, sep, quote) {
        return hit(key + sep + quote + REDACTED + quote);
    });

    if (opts.pii) {
        s = s.replace(SSN, function () { return hit(REDACTED); });
        s = s.replace(CARD, function (m) {
            var digits = m.replace(/[^0-9]/g, '');
            if (digits.length < 13 || digits.length > 19 || !luhn(digits)) { return m; }
            return hit(REDACTED);
        });
        s = s.replace(PHONE, function () { return hit(REDACTED); });
    }

    /* Rule (c) last: by this point a masked credential has no address left in
       it for this to match against. */
    return maskEmails(s);
}

function scrub(node, depth, opts) {
    depth = depth || 0;
    if (depth > MAX_DEPTH) { return null; }

    if (node === null || node === undefined) { return node; }

    if (Object.prototype.toString.call(node) === '[object Array]') {
        var arr = [];
        for (var i = 0; i < node.length; i++) { arr.push(scrub(node[i], depth + 1, opts)); }
        return arr;
    }

    if (typeof node === 'object') {
        var out = {};
        for (var k in node) {
            if (!Object.prototype.hasOwnProperty.call(node, k)) { continue; }
            if (SENSITIVE_KEY.test(k)) {        // rule (a): value replaced, key kept
                out[k] = REDACTED;
                HITS++;
                continue;
            }
            out[k] = scrub(node[k], depth + 1, opts);
        }
        return out;
    }

    if (typeof node === 'string') { return redactText(node, opts); }   // rules (b)-(d)

    return node;
}

/* A body worth scanning as text: anything human-readable. An unrecognised or
   binary type is left alone and *recorded* as left alone, because a redactor
   that silently passes a content type through is indistinguishable from one
   that scanned it and found nothing. */
function isTextual(ctype) {
    if (!ctype) { return true; }                    // absent header: assume text and scan
    return ctype.indexOf('text/') >= 0 ||
        ctype.indexOf('xml') >= 0 ||
        ctype.indexOf('yaml') >= 0 ||
        ctype.indexOf('markdown') >= 0 ||
        ctype.indexOf('x-www-form-urlencoded') >= 0;
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var ctype = (context.getVariable('response.header.Content-Type') || '').toLowerCase();
    var raw = context.getVariable('response.content');
    /* Rule (d) is opt-in per proxy, via a variable set before the shared flow
       runs. Unset means off, which is the documented default. */
    var opts = { pii: String(context.getVariable('airlock.redact.pii') || '') === 'true' };

    HITS = 0;
    if (raw) {
        if (ctype.indexOf('json') >= 0) {
            try {
                context.setVariable('response.content', JSON.stringify(scrub(JSON.parse(raw), 0, opts)));
            } catch (e) {
                /* Declared JSON that does not parse is not a reason to stop
                   scanning the body -- it is a reason to stop trusting the
                   header. The old behaviour was to leave it untouched, which
                   made "return a secret under a broken Content-Type" a
                   complete bypass of this policy. Fall back to the text
                   scanner instead, and record why. */
                context.setVariable('airlock.redact.error', String(e));
                context.setVariable('response.content', redactText(raw, opts));
            }
        } else if (isTextual(ctype)) {
            /* text/plain, and the media types GitHub uses for .diff and .patch.
               The old gate matched 'json' only, so any of these left the
               gateway unscanned. */
            context.setVariable('response.content', redactText(raw, opts));
        } else {
            context.setVariable('airlock.redact.skipped', ctype);
        }
    }
    context.setVariable('airlock.redact.hits', HITS);
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        scrub: scrub,
        maskEmails: maskEmails,
        redactText: redactText,
        isTextual: isTextual,
        REDACTED: REDACTED,
        SENSITIVE_KEY: SENSITIVE_KEY,
        hits: function () { return HITS; },
        resetHits: function () { HITS = 0; }
    };
}
