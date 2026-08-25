/*
 * slack_message.js -- rebuilds an outbound Slack "post message" payload.
 *
 * Runs inside Apigee's Rhino engine (ES5 only) but the pure function is
 * require()-able under Node for unit tests, same arrangement as github_issue.js.
 *
 * Why this is JavaScript and not an AssignMessage template: the message text is
 * attacker-controlled. Interpolating it into a JSON string template breaks on an
 * embedded quote and, worse, lets a caller inject sibling fields -- `blocks`,
 * `attachments`, `username`, `icon_url` -- which would let an agent post as
 * somebody else, or smuggle interactive elements into a channel. JSON.stringify
 * cannot be escaped out of, so the field set is fixed by construction.
 *
 * The second job is mention neutralisation, and it is the Slack analogue of
 * github_issue.js dropping `assignees`. Slack only turns bare "@channel" into a
 * broadcast when the caller sets link_names, which this never does -- but the
 * raw markup <!channel>, <!here>, <!everyone>, <@U…> and <!subteam^…> pings
 * people straight out of the message text, with no separate field to strip. An
 * agent that can be talked into posting "<!channel> urgent" can page an entire
 * workspace at 3am, so the markup is defused into its plain-text appearance:
 * the message still reads the way its author wrote it, and nobody's phone
 * lights up.
 */

var MAX_TEXT = 4000;

/* Slack's mention markup, all of which notify. Rewritten to the visible text a
   reader would have seen anyway, so the message is not silently mangled. */
function defuse(text) {
    return String(text)
        .replace(/<!(channel|here|everyone)(\|[^>]*)?>/g, '@$1')
        /* Two capture groups here, not three: the subteam id is not captured,
           so the callback's third argument is replace()'s offset, not a label. */
        .replace(/<!subteam\^[A-Za-z0-9]+(\|([^>]*))?>/g, function (m, pipe, label) {
            return label ? label : '@group';
        })
        .replace(/<@([A-Za-z0-9]+)(\|([^>]*))?>/g, function (m, id, pipe, label) {
            return label ? '@' + label : '@' + id;
        });
}

function buildMessage(raw) {
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

    var channel = parsed.channel;
    if (typeof channel !== 'string' || channel.replace(/^\s+|\s+$/g, '') === '') {
        return { error: 'missing_channel' };
    }
    channel = channel.replace(/^\s+|\s+$/g, '');

    var text = parsed.text;
    if (typeof text !== 'string' || text.replace(/^\s+|\s+$/g, '') === '') {
        return { error: 'missing_text' };
    }
    if (text.length > MAX_TEXT) { text = text.substring(0, MAX_TEXT); }
    text = defuse(text);

    /* Only these two fields survive. blocks, attachments, username, icon_emoji,
       icon_url, link_names, reply_broadcast, unfurl_links and everything else
       Slack would accept are dropped: an agent must not be able to impersonate,
       to broadcast, or to post anything a human cannot read as plain text. */
    var out = { channel: channel, text: text };
    return { json: JSON.stringify(out), channel: channel, text: text };
}

/* ---- Apigee glue: only runs inside the gateway, skipped under Node ---- */
if (typeof context !== 'undefined' && context !== null) {
    var result = buildMessage(context.getVariable('request.content') || '');
    if (result.error) {
        context.setVariable('airlock.message.error', result.error);
    } else {
        context.setVariable('request.content', result.json);
        context.setVariable('request.header.Content-Type', 'application/json; charset=utf-8');
        /* The channel the allowlist check will run against. Taken from the
           rebuilt payload rather than from the raw body, so what is checked is
           exactly what will be sent -- a duplicate "channel" key, or one in the
           query string, cannot make the two disagree. */
        context.setVariable('slack.channel', result.channel);
        /* Handed to the audit log, which runs long after the body is gone.
           An outbound write is the thing an audit exists to reconstruct, and
           "agent-operator posted to C09ABCDEF" is only answerable as "posted
           what". This is the same call github_issue.js makes for issue titles,
           and the opposite of the rule llm-v1 follows for prompts -- a prompt is
           input to a model, a message is an action taken on the world. */
        context.setVariable('airlock.message.text', result.text);
    }
}

/* ---- Node test hook ---- */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { buildMessage: buildMessage, defuse: defuse, MAX_TEXT: MAX_TEXT };
}
