/*
 * Unit tests for shared/js/redact.js -- the pure functions only.
 *
 * The module guards its Apigee glue behind `typeof context !== 'undefined'`,
 * so requiring it under Node exercises scrub()/redactText()/maskEmails() in
 * isolation.
 * Run: node tests/test_redact.js
 *
 * Every credential-shaped string below is a fixture: correct in shape, and
 * deliberately built out of repeated characters so that nothing here is, or
 * ever was, a working token.
 */
var assert = require('assert');
var path = require('path');
var r = require(path.join(__dirname, '..', 'shared', 'js', 'redact.js'));

var R = r.REDACTED;
var failures = 0;
function t(name, fn) {
    try { r.resetHits(); fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

/* Asserts the secret is gone AND that a marker replaced it -- "gone" alone
   would pass on a rule that simply deleted the whole string. */
function gone(actual, secret) {
    assert.strictEqual(actual.indexOf(secret), -1, 'secret survived in: ' + actual);
    assert.notStrictEqual(actual.indexOf(R), -1, 'no marker left behind in: ' + actual);
}

/* ---- rule (a): credential-shaped keys are masked ---- */

t('masks the value of top-level credential keys', function () {
    var out = r.scrub({ access_token: 'abc', api_key: 'sk-1', keep: 1 });
    assert.deepStrictEqual(out, { access_token: R, api_key: R, keep: 1 });
});

t('masks keys in every naming style', function () {
    var out = r.scrub({
        'api_key': 1, 'api-key': 1, 'apiKey': 1, 'API_KEY': 1,
        'authorization': 1, 'Authorization': 1,
        'refresh_token': 1, 'refreshToken': 1, 'token': 1,
        'secret': 1, 'client_secret': 1,
        'password': 1, 'passwd': 1, 'credential': 1,
        'safe': 1
    });
    assert.strictEqual(out.safe, 1);
    for (var k in out) {
        if (k !== 'safe') { assert.strictEqual(out[k], R, k + ' was not masked'); }
    }
});

t('masks nested and in-array credential keys', function () {
    var out = r.scrub({ a: { b: { token: 'x', ok: 2 } }, list: [{ password: 'p', id: 7 }] });
    assert.deepStrictEqual(out, { a: { b: { token: R, ok: 2 } }, list: [{ password: R, id: 7 }] });
});

t('does not mask keys that merely contain a sensitive word', function () {
    // "tokenizer" is not a credential; the pattern is delimiter-anchored.
    var out = r.scrub({ tokenizer: 'bpe' });
    assert.strictEqual(out.tokenizer, 'bpe');
});

t('the key rule leaves a marker rather than a hole', function () {
    // A deleted key is indistinguishable from one the backend never sent, which
    // is exactly the ambiguity a model fills in by guessing.
    var out = r.scrub({ token: 'ghp_secret' });
    assert.ok(Object.prototype.hasOwnProperty.call(out, 'token'));
    assert.strictEqual(out.token, R);
});

/* ---- rule (b): credential-shaped *values*, the read-path gap ---- */

t('masks vendor-prefixed tokens in free text', function () {
    var cases = [
        'ghp_' + new Array(37).join('A'),
        'github_pat_' + new Array(23).join('B') + '_' + new Array(20).join('C'),
        'xoxb-1111111111-2222222222-' + new Array(25).join('D'),
        'xapp-1-A01ABCDEFGH-1234567890-' + new Array(20).join('E'),
        'sk-or-v1-' + new Array(41).join('f'),
        'sk-proj-' + new Array(41).join('g'),
        'sk-' + new Array(41).join('h'),
        'glpat-' + new Array(21).join('J'),
        'AKIAIOSFODNN7EXAMPLE',
        'AIza' + new Array(36).join('K'),
        'ya29.' + new Array(30).join('L')
    ];
    for (var i = 0; i < cases.length; i++) {
        var body = 'the key is ' + cases[i] + ' please rotate it';
        gone(r.redactText(body), cases[i]);
    }
});

t('sk-or-v1- is not shortened to sk- by alternation order', function () {
    var key = 'sk-or-v1-' + new Array(41).join('f');
    var out = r.redactText('OPENROUTER key was ' + key);
    // A leftmost-first alternation that put sk- early would leave "or-v1-fff..."
    assert.strictEqual(out.indexOf('or-v1-'), -1, 'partial match left a tail: ' + out);
});

t('masks a JWT', function () {
    var jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r5wW1gFWFOEjXk';
    gone(r.redactText('session is ' + jwt), jwt);
});

t('masks a whole PEM private key block, not just its header', function () {
    var pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow' + new Array(40).join('x') +
        '\n' + new Array(40).join('y') + '\n-----END RSA PRIVATE KEY-----';
    var out = r.redactText('deploy key:\n' + pem + '\nthanks');
    assert.strictEqual(out.indexOf('MIIEow'), -1, 'key body survived');
    assert.strictEqual(out.indexOf('BEGIN RSA'), -1, 'key header survived');
    assert.notStrictEqual(out.indexOf('thanks'), -1, 'ate text past the END line');
});

t('masks an unlabelled PEM block too', function () {
    var pem = '-----BEGIN PRIVATE KEY-----\nMIIBVg' + new Array(30).join('z') + '\n-----END PRIVATE KEY-----';
    gone(r.redactText(pem), 'MIIBVg');
});

t('masks credentials embedded in a URL but keeps the host', function () {
    var out = r.redactText('git remote add origin https://sam:ghp_abcdefabcdef@github.com/acme/app.git');
    assert.strictEqual(out.indexOf('ghp_abcdefabcdef'), -1, 'PAT survived');
    assert.strictEqual(out.indexOf('sam:'), -1, 'username survived');
    assert.notStrictEqual(out.indexOf('github.com/acme/app.git'), -1, 'host was eaten');
});

t('masks a database connection string', function () {
    var out = r.redactText('DSN: postgres://svc:hunter2@db.internal:5432/prod');
    gone(out, 'hunter2');
    assert.notStrictEqual(out.indexOf('db.internal:5432/prod'), -1, 'host was eaten');
});

t('masks a Slack incoming webhook URL', function () {
    var hook = 'https://hooks.slack.com/services/T00000000/B00000000/' + new Array(25).join('m');
    gone(r.redactText('post to ' + hook), hook);
});

t('masks an Authorization header pasted from curl, keeping the scheme', function () {
    var out = r.redactText('curl -H "Authorization: Bearer ' + new Array(41).join('t') + '" https://api');
    assert.strictEqual(out.indexOf('tttt'), -1, 'credential survived: ' + out);
    assert.notStrictEqual(out.toLowerCase().indexOf('bearer'), -1, 'scheme was lost');
});

t('masks Basic auth as readily as Bearer', function () {
    gone(r.redactText('authorization: Basic dXNlcjpwYXNzd29yZA=='), 'dXNlcjpwYXNzd29yZA');
});

t('masks labelled key-values in prose', function () {
    var cases = [
        ['password: hunter2', 'hunter2'],
        ['PASSWORD=hunter2', 'hunter2'],
        ['api_key = abc123def', 'abc123def'],
        ['"client_secret":"s3cr3tvalue"', 's3cr3tvalue'],
        ["pwd='letmein'", 'letmein'],
        ['ACCESS_TOKEN=abcdef123456', 'abcdef123456']
    ];
    for (var i = 0; i < cases.length; i++) {
        gone(r.redactText(cases[i][0]), cases[i][1]);
    }
});

t('leaves the label in place so the reader knows what was withheld', function () {
    assert.strictEqual(r.redactText('password: hunter2').indexOf('password'), 0);
});

t('does not fire on ordinary prose', function () {
    var prose = 'The token bucket refills every second and the password policy ' +
        'requires rotation. See the secret sauce doc. Tokenizer settings unchanged.';
    assert.strictEqual(r.redactText(prose), prose);
    assert.strictEqual(r.hits(), 0);
});

t('does not fire on a UUID or a git sha', function () {
    var s = 'commit 9f2b1c4e8a7d6b5c3e1f0a9b8c7d6e5f4a3b2c1d in 3f2504e0-4f89-11d3-9a0c-0305e82c3301';
    assert.strictEqual(r.redactText(s), s);
});

/* ---- the case that started this: a secret inside a GitHub issue body ---- */

t('masks a secret pasted into an issue body', function () {
    var issue = {
        number: 42,
        title: 'Deploy fails with password: hunter2',
        body: 'Repro:\n  export GITHUB_TOKEN=ghp_' + new Array(37).join('A') +
              '\n  curl -H "Authorization: Bearer ' + new Array(41).join('t') + '" https://api\n' +
              'contact alice@example.com',
        user: { login: 'sam', id: 9 }
    };
    var out = r.scrub(issue);
    var flat = JSON.stringify(out);
    assert.strictEqual(flat.indexOf('hunter2'), -1, 'title secret survived');
    assert.strictEqual(flat.indexOf('ghp_AAA'), -1, 'body PAT survived');
    assert.strictEqual(flat.indexOf('tttt'), -1, 'bearer token survived');
    assert.strictEqual(out.number, 42, 'non-string fields must pass through');
    assert.strictEqual(out.user.login, 'sam', 'ordinary text must pass through');
    assert.notStrictEqual(out.body.indexOf('a***@example.com'), -1, 'email rule stopped working');
});

/* ---- rule (c): emails ---- */

t('masks a bare email', function () {
    assert.strictEqual(r.maskEmails('alice@example.com'), 'a***@example.com');
});

t('masks emails embedded in prose, several per string', function () {
    assert.strictEqual(
        r.maskEmails('ping bob@example.org or carol@sub.example.co.uk now'),
        'ping b***@example.org or c***@sub.example.co.uk now');
});

t('masks emails inside nested values', function () {
    var out = r.scrub({ contact: { addr: 'dave@example.net' } });
    assert.strictEqual(out.contact.addr, 'd***@example.net');
});

t('leaves non-email text untouched', function () {
    assert.strictEqual(r.maskEmails('no address here @ all'), 'no address here @ all');
});

/* ---- rule (d): opt-in PII ---- */

t('leaves SSN, card and phone alone by default', function () {
    var s = 'ssn 123-45-6789 card 4111 1111 1111 1111 tel +1 415 555 0132';
    assert.strictEqual(r.redactText(s), s);
});

t('masks SSN, a Luhn-valid card and a phone when pii is on', function () {
    var out = r.redactText('ssn 123-45-6789 card 4111 1111 1111 1111 tel +1 415 555 0132', { pii: true });
    assert.strictEqual(out.indexOf('123-45-6789'), -1, 'SSN survived');
    assert.strictEqual(out.indexOf('4111'), -1, 'card survived');
    assert.strictEqual(out.indexOf('555 0132'), -1, 'phone survived');
});

t('leaves a Luhn-invalid digit run alone even with pii on', function () {
    // A 16-digit build identifier is not a payment card, and treating it as one
    // is how a redactor earns a reputation for corrupting responses.
    var s = 'build 1234567890123456 ok';
    assert.strictEqual(r.redactText(s, { pii: true }), s);
});

t('pii option reaches string values through scrub', function () {
    var out = r.scrub({ body: 'ssn 123-45-6789' }, 0, { pii: true });
    assert.strictEqual(out.body.indexOf('123-45-6789'), -1);
});

/* ---- content-type gate ---- */

t('treats text and text-adjacent types as scannable', function () {
    assert.strictEqual(r.isTextual('text/plain; charset=utf-8'), true);
    assert.strictEqual(r.isTextual('application/xml'), true);
    assert.strictEqual(r.isTextual('text/markdown'), true);
    assert.strictEqual(r.isTextual('application/x-www-form-urlencoded'), true);
    assert.strictEqual(r.isTextual(''), true);          // absent header: scan it
});

t('treats binary types as unscannable', function () {
    assert.strictEqual(r.isTextual('image/png'), false);
    assert.strictEqual(r.isTextual('application/octet-stream'), false);
});

/* ---- the hit counter ---- */

t('counts value matches and key matches together', function () {
    r.resetHits();
    r.scrub({ token: 'x', body: 'password: hunter2' });
    assert.strictEqual(r.hits(), 2);
});

t('reports zero on a clean response', function () {
    r.resetHits();
    r.scrub({ number: 1, title: 'a normal issue', user: { login: 'sam' } });
    assert.strictEqual(r.hits(), 0);
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
    assert.deepStrictEqual(r.scrub([{ secret: 's', id: 1 }]), [{ secret: R, id: 1 }]);
});

t('handles an empty string and a non-string without throwing', function () {
    assert.strictEqual(r.redactText(''), '');
    assert.strictEqual(r.redactText(null), null);
    assert.strictEqual(r.redactText(7), 7);
});

t('scanning twice gives the same answer', function () {
    // Guards the /g lastIndex trap: a shared global regex used statefully would
    // match on the first pass and skip on the second.
    var s = 'a ghp_' + new Array(37).join('A') + ' and ghp_' + new Array(37).join('B');
    var once = r.redactText(s);
    assert.strictEqual(r.redactText(s), once);
    assert.strictEqual(once.indexOf('ghp_'), -1, 'second token survived: ' + once);
});

console.log(failures === 0 ? 'redact.js: all tests passed' : 'redact.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
