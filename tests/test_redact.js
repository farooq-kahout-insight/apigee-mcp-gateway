/*
 * Unit tests for shared/js/redact.js -- the pure functions only.
 *
 * The module guards its Apigee glue behind `typeof context !== 'undefined'`,
 * so requiring it under Node exercises scrub()/maskEmails() in isolation.
 * Run: node tests/test_redact.js
 */
var assert = require('assert');
var path = require('path');
var r = require(path.join(__dirname, '..', 'shared', 'js', 'redact.js'));

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

/* ---- rule (a): credential-shaped keys are dropped ---- */

t('drops top-level credential keys', function () {
    var out = r.scrub({ access_token: 'abc', api_key: 'sk-1', keep: 1 });
    assert.deepStrictEqual(out, { keep: 1 });
});

t('drops keys in every naming style', function () {
    var out = r.scrub({
        'api_key': 1, 'api-key': 1, 'apiKey': 1, 'API_KEY': 1,
        'authorization': 1, 'Authorization': 1,
        'refresh_token': 1, 'refreshToken': 1, 'token': 1,
        'secret': 1, 'client_secret': 1,
        'password': 1, 'passwd': 1, 'credential': 1,
        'safe': 1
    });
    assert.deepStrictEqual(out, { safe: 1 });
});

t('drops nested and in-array credential keys', function () {
    var out = r.scrub({ a: { b: { token: 'x', ok: 2 } }, list: [{ password: 'p', id: 7 }] });
    assert.deepStrictEqual(out, { a: { b: { ok: 2 } }, list: [{ id: 7 }] });
});

t('does not drop keys that merely contain a sensitive word', function () {
    // "tokenizer" is not a credential; the pattern is delimiter-anchored.
    var out = r.scrub({ tokenizer: 'bpe', password_hint_shown: true });
    assert.strictEqual(out.tokenizer, 'bpe');
});

/* ---- rule (b): emails are masked ---- */

t('masks a bare email', function () {
    assert.strictEqual(r.maskEmails('alice@example.com'), 'a***@example.com');
});

t('masks emails embedded in prose, several per string', function () {
    assert.strictEqual(
        r.maskEmails('ping bob@example.org or carol@sub.example.co.uk now'),
        'ping b***@example.org or c***@sub.example.co.uk now');
});

t('masks emails inside nested values', function () {
    var out = r.scrub({ contact: { email: 'dave@example.net' } });
    assert.strictEqual(out.contact.email, 'd***@example.net');
});

t('leaves non-email text untouched', function () {
    assert.strictEqual(r.maskEmails('no address here @ all'), 'no address here @ all');
});

/* ---- structural safety ---- */

t('preserves non-string scalars and null', function () {
    var out = r.scrub({ n: 42, b: false, z: null, f: 1.5 });
    assert.deepStrictEqual(out, { n: 42, b: false, z: null, f: 1.5 });
});

t('preserves array order and nesting', function () {
    assert.deepStrictEqual(r.scrub([1, [2, [3]], { a: 4 }]), [1, [2, [3]], { a: 4 }]);
});

t('truncates runaway depth instead of blowing the stack', function () {
    var deep = {}, cur = deep;
    for (var i = 0; i < 60; i++) { cur.n = {}; cur = cur.n; }
    cur.token = 'leak';
    var out = r.scrub(deep);           // must return, not throw
    assert.strictEqual(JSON.stringify(out).indexOf('leak'), -1);
});

t('handles a top-level array of credential-bearing objects', function () {
    assert.deepStrictEqual(r.scrub([{ secret: 's', id: 1 }]), [{ id: 1 }]);
});

console.log(failures === 0 ? 'redact.js: all tests passed' : 'redact.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
