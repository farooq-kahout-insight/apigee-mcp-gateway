/*
 * Unit tests for shared/js/slack_message.js.
 * Run: node tests/test_slack_message.js
 */
var assert = require('assert');
var path = require('path');
var s = require(path.join(__dirname, '..', 'shared', 'js', 'slack_message.js'));

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

t('keeps channel and text', function () {
    var r = s.buildMessage(JSON.stringify({ channel: 'C09ABCDEF', text: 'deploy done' }));
    assert.deepStrictEqual(JSON.parse(r.json), { channel: 'C09ABCDEF', text: 'deploy done' });
});

t('drops every field outside the allowlist', function () {
    var r = s.buildMessage(JSON.stringify({
        channel: 'C09ABCDEF', text: 'hi',
        blocks: [{ type: 'section' }], attachments: [{ text: 'x' }],
        username: 'Head of Security', icon_emoji: ':lock:', icon_url: 'http://x/y.png',
        link_names: true, reply_broadcast: true, thread_ts: '1.2', unfurl_links: true
    }));
    assert.deepStrictEqual(Object.keys(JSON.parse(r.json)).sort(), ['channel', 'text']);
});

t('a quote in the text cannot break out of the JSON', function () {
    var nasty = 'he said "ship it"';
    var r = s.buildMessage(JSON.stringify({ channel: 'C1', text: nasty }));
    assert.strictEqual(JSON.parse(r.json).text, nasty);
});

t('text that looks like JSON cannot inject sibling fields', function () {
    var inject = 'x", "username": "ceo", "z": "';
    var r = s.buildMessage(JSON.stringify({ channel: 'C1', text: inject }));
    var out = JSON.parse(r.json);
    assert.deepStrictEqual(Object.keys(out).sort(), ['channel', 'text']);
    assert.strictEqual(out.text, inject);
});

/* ---- mention neutralisation: the reason this file is JavaScript ---- */

t('defuses @channel, @here and @everyone', function () {
    assert.strictEqual(s.defuse('<!channel> deploy failed'), '@channel deploy failed');
    assert.strictEqual(s.defuse('<!here> ping'), '@here ping');
    assert.strictEqual(s.defuse('<!everyone> ping'), '@everyone ping');
});

t('defuses the labelled broadcast form', function () {
    assert.strictEqual(s.defuse('<!channel|@channel> up'), '@channel up');
});

t('defuses a user mention, with and without a label', function () {
    assert.strictEqual(s.defuse('cc <@U123ABC>'), 'cc @U123ABC');
    assert.strictEqual(s.defuse('cc <@U123ABC|alice>'), 'cc @alice');
});

t('defuses a subteam mention wherever it sits in the string', function () {
    // Regression: the callback once read replace()'s offset as the label, so a
    // subteam mention anywhere but index 0 rendered as its own character offset.
    assert.strictEqual(s.defuse('<!subteam^S0100|@ops>'), '@ops');
    assert.strictEqual(s.defuse('paging <!subteam^S0100|@ops> now'), 'paging @ops now');
    assert.strictEqual(s.defuse('paging <!subteam^S0100> now'), 'paging @group now');
});

t('defuses every mention in a message, not just the first', function () {
    assert.strictEqual(
        s.defuse('<!channel> and <@U1> and <!here>'),
        '@channel and @U1 and @here');
});

t('buildMessage defuses the text it sends and the text it audits', function () {
    var r = s.buildMessage(JSON.stringify({ channel: 'C1', text: '<!channel> 3am' }));
    assert.strictEqual(JSON.parse(r.json).text, '@channel 3am');
    assert.strictEqual(r.text, '@channel 3am');
});

t('leaves ordinary angle brackets and links alone', function () {
    assert.strictEqual(s.defuse('a < b > c'), 'a < b > c');
    assert.strictEqual(s.defuse('<https://example.com|docs>'), '<https://example.com|docs>');
});

/* ---- rejections ---- */

t('rejects a missing channel', function () {
    assert.strictEqual(s.buildMessage(JSON.stringify({ text: 'hi' })).error, 'missing_channel');
});

t('rejects a blank or non-string channel', function () {
    assert.strictEqual(s.buildMessage(JSON.stringify({ channel: '  ', text: 'hi' })).error, 'missing_channel');
    assert.strictEqual(s.buildMessage(JSON.stringify({ channel: 42, text: 'hi' })).error, 'missing_channel');
});

t('rejects a missing, blank or non-string text', function () {
    assert.strictEqual(s.buildMessage(JSON.stringify({ channel: 'C1' })).error, 'missing_text');
    assert.strictEqual(s.buildMessage(JSON.stringify({ channel: 'C1', text: '\n\t ' })).error, 'missing_text');
    assert.strictEqual(s.buildMessage(JSON.stringify({ channel: 'C1', text: ['hi'] })).error, 'missing_text');
});

t('rejects an unparseable body', function () {
    assert.strictEqual(s.buildMessage('not json at all').error, 'unparseable');
    assert.strictEqual(s.buildMessage('').error, 'unparseable');
});

t('rejects a top-level array', function () {
    assert.strictEqual(s.buildMessage('[{"channel":"C1","text":"hi"}]').error, 'not_an_object');
});

t('rejects a JSON null body', function () {
    assert.strictEqual(s.buildMessage('null').error, 'not_an_object');
});

t('trims the channel it checks and sends', function () {
    var r = s.buildMessage(JSON.stringify({ channel: '  C09ABCDEF  ', text: 'hi' }));
    assert.strictEqual(r.channel, 'C09ABCDEF');
    assert.strictEqual(JSON.parse(r.json).channel, 'C09ABCDEF');
});

t('truncates over-long text instead of rejecting it', function () {
    var long = new Array(s.MAX_TEXT + 100).join('b');
    var r = s.buildMessage(JSON.stringify({ channel: 'C1', text: long }));
    assert.strictEqual(JSON.parse(r.json).text.length, s.MAX_TEXT);
});

t('the channel checked is the channel sent', function () {
    // The allowlist runs against result.channel; if that could differ from the
    // body's channel, an allowlisted read would authorise a non-allowlisted post.
    var r = s.buildMessage(JSON.stringify({ channel: 'C09ABCDEF', text: 'hi' }));
    assert.strictEqual(r.channel, JSON.parse(r.json).channel);
});

console.log(failures === 0 ? 'slack_message.js: all tests passed' : 'slack_message.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
