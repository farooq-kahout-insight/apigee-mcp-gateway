/*
 * github_issue.js -- rebuilds an outbound GitHub "create issue" payload.
 *
 * Runs inside Apigee's Rhino engine (ES5 only) but the pure function is
 * require()-able under Node for unit tests, same arrangement as redact.js.
 *
 * Why this is JavaScript and not an AssignMessage template: the title is
 * attacker-controlled text. Interpolating it into a JSON string template
 * ({"title":"{var}"}) breaks on an embedded quote and, worse, lets a caller
 * inject sibling fields such as "assignees". JSON.stringify cannot be escaped
 * out of, so the field set is fixed by construction.
 */

var MAX_TITLE = 256;
var MAX_BODY = 65536;

function buildIssue(raw) {
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

    var title = parsed.title;
    if (typeof title !== 'string' || title.replace(/^\s+|\s+$/g, '') === '') {
        return { error: 'missing_title' };
    }
    if (title.length > MAX_TITLE) { return { error: 'title_too_long' }; }

    // Only these two fields survive. assignees, labels, milestone and anything
    // else GitHub would accept are dropped -- an agent must not be able to
    // notify or tag people through this gateway.
    var out = { title: title };
    if (typeof parsed.body === 'string') {
        out.body = parsed.body.length > MAX_BODY ? parsed.body.substring(0, MAX_BODY) : parsed.body;
    }
    return { json: JSON.stringify(out) };
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var result = buildIssue(context.getVariable('request.content') || '');
    if (result.error) {
        context.setVariable('airlock.issue.error', result.error);
    } else {
        context.setVariable('request.content', result.json);
        context.setVariable('request.header.Content-Type', 'application/json');
    }
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { buildIssue: buildIssue, MAX_TITLE: MAX_TITLE, MAX_BODY: MAX_BODY };
}
