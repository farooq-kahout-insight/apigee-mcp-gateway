/*
 * Unit tests for shared/js/slack_outcome.js.
 * Run: node tests/test_slack_outcome.js
 */
var assert = require('assert');
var path = require('path');
var s = require(path.join(__dirname, '..', 'shared', 'js', 'slack_outcome.js'));

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

function err(name) { return JSON.stringify({ ok: false, error: name }); }

/* ---- the cases where there is nothing to translate ---- */

t('a successful call is left alone', function () {
    assert.strictEqual(s.outcome(200, JSON.stringify({ ok: true, ts: '1.2' })), null);
});

t('a non-2xx status is left alone even with ok:false in the body', function () {
    // Slack's own 429 and 5xx already say what they mean; rewriting them from
    // the body would lose information rather than add it.
    assert.strictEqual(s.outcome(429, err('ratelimited')), null);
    assert.strictEqual(s.outcome(500, err('fatal_error')), null);
    assert.strictEqual(s.outcome(403, err('not_in_channel')), null);
});

t('an unparseable or non-object body is left alone', function () {
    assert.strictEqual(s.outcome(200, '<html>maintenance</html>'), null);
    assert.strictEqual(s.outcome(200, ''), null);
    assert.strictEqual(s.outcome(200, 'null'), null);
    assert.strictEqual(s.outcome(200, '"just a string"'), null);
});

t('a body without ok:false is left alone', function () {
    assert.strictEqual(s.outcome(200, JSON.stringify({ messages: [] })), null);
    assert.strictEqual(s.outcome(200, JSON.stringify({ ok: 'false' })), null);
});

/* ---- the translation itself ---- */

t('200 + ok:false becomes a real failure status', function () {
    var v = s.outcome(200, err('not_in_channel'));
    assert.strictEqual(v.status, 403);
    assert.strictEqual(v.error, 'forbidden');
});

t('permission errors map to 403', function () {
    var denied = ['not_in_channel', 'channel_not_found', 'is_archived', 'missing_scope',
                  'not_allowed_token_type', 'no_permission', 'restricted_action',
                  'restricted_action_read_only_channel', 'ekm_access_denied',
                  'org_login_required'];
    for (var i = 0; i < denied.length; i++) {
        assert.strictEqual(s.classify(denied[i]).status, 403, denied[i]);
    }
});

t('a bad KVM token is 502, not 401', function () {
    // 401 would tell the agent its own consumer key was rejected and send an
    // operator hunting through Apigee for a fault that lives in the KVM.
    var auth = ['invalid_auth', 'not_authed', 'token_revoked', 'token_expired',
                'account_inactive', 'no_permission_bot'];
    for (var i = 0; i < auth.length; i++) {
        var v = s.classify(auth[i]);
        assert.strictEqual(v.status, 502, auth[i]);
        assert.strictEqual(v.error, 'upstream_error', auth[i]);
    }
});

t('rate limiting maps to 429 in both spellings', function () {
    assert.strictEqual(s.classify('ratelimited').status, 429);
    assert.strictEqual(s.classify('rate_limited').status, 429);
    assert.strictEqual(s.classify('ratelimited').error, 'rate_limited');
});

t('Slack-side faults map to 502', function () {
    assert.strictEqual(s.classify('fatal_error').status, 502);
    assert.strictEqual(s.classify('internal_error').status, 502);
    assert.strictEqual(s.classify('service_unavailable').status, 502);
});

t('an unrecognised error is the caller\'s fault by default', function () {
    assert.strictEqual(s.classify('msg_too_long').status, 400);
    assert.strictEqual(s.classify('something_slack_shipped_last_week').status, 400);
    assert.strictEqual(s.classify('').status, 400);
    assert.strictEqual(s.classify(undefined).status, 400);
});

/* ---- what the caller is allowed to learn ---- */

t('Slack\'s error string never reaches the caller', function () {
    // channel_not_found vs not_in_channel tells an agent whether a channel it
    // guessed at exists -- the enumeration RF-Channel-Denied exists to prevent,
    // arriving by another door.
    var v = s.outcome(200, err('channel_not_found'));
    assert.strictEqual(v.message.indexOf('channel_not_found'), -1);
    assert.strictEqual(v.error, 'forbidden');
});

t('the two 403 shapes are indistinguishable to the caller', function () {
    var a = s.outcome(200, err('channel_not_found'));
    var b = s.outcome(200, err('not_in_channel'));
    assert.strictEqual(a.status, b.status);
    assert.strictEqual(a.message, b.message);
});

t('the error string is kept for the audit, where the reader is trusted', function () {
    assert.strictEqual(s.outcome(200, err('missing_scope')).slackError, 'missing_scope');
});

t('an ok:false with no error string still audits as something', function () {
    var v = s.outcome(200, JSON.stringify({ ok: false }));
    assert.strictEqual(v.status, 400);
    assert.strictEqual(v.slackError, 'unknown');
});

t('every verdict carries a reason phrase and a JSON-safe message', function () {
    var cases = ['not_in_channel', 'invalid_auth', 'ratelimited', 'fatal_error', 'msg_too_long'];
    for (var i = 0; i < cases.length; i++) {
        var v = s.classify(cases[i]);
        assert.ok(v.reason && typeof v.reason === 'string', cases[i]);
        assert.strictEqual(JSON.parse(JSON.stringify({ e: v.error, m: v.message })).m, v.message);
    }
});

console.log(failures === 0 ? 'slack_outcome.js: all tests passed' : 'slack_outcome.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
