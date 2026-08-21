/*
 * redact.js -- response scrubber for the agent-airlock gateway.
 *
 * Runs inside Apigee's Rhino engine (ES5 only: no let/const, no arrow functions)
 * but is written so the pure functions can be require()'d by Node for unit tests.
 *
 * Rules:
 *   (a) drop any object key matching token|secret|password|api_key|authorization
 *   (b) mask email addresses -> first char + ***@domain
 */

var SENSITIVE_KEY = /(^|[_\-.])?(authorization|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|token|secret|client[_\-]?secret|password|passwd|credential)([_\-.]|$)/i;
var EMAIL = /([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})/g;
var MAX_DEPTH = 20;

function maskEmails(s) {
    return s.replace(EMAIL, function (_m, first, domain) {
        return first + '***@' + domain;
    });
}

function scrub(node, depth) {
    depth = depth || 0;
    if (depth > MAX_DEPTH) { return null; }

    if (node === null || node === undefined) { return node; }

    if (Object.prototype.toString.call(node) === '[object Array]') {
        var arr = [];
        for (var i = 0; i < node.length; i++) { arr.push(scrub(node[i], depth + 1)); }
        return arr;
    }

    if (typeof node === 'object') {
        var out = {};
        for (var k in node) {
            if (!Object.prototype.hasOwnProperty.call(node, k)) { continue; }
            if (SENSITIVE_KEY.test(k)) { continue; }   // rule (a): drop entirely
            out[k] = scrub(node[k], depth + 1);
        }
        return out;
    }

    if (typeof node === 'string') { return maskEmails(node); }   // rule (b)

    return node;
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var ctype = context.getVariable('response.header.Content-Type') || '';
    if (ctype.toLowerCase().indexOf('json') >= 0) {
        var raw = context.getVariable('response.content');
        if (raw) {
            try {
                context.setVariable('response.content', JSON.stringify(scrub(JSON.parse(raw), 0)));
            } catch (e) {
                // Unparseable body: leave it alone rather than leaking a parser error.
                context.setVariable('airlock.redact.error', String(e));
            }
        }
    }
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { scrub: scrub, maskEmails: maskEmails, SENSITIVE_KEY: SENSITIVE_KEY };
}
