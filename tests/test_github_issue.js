/*
 * Unit tests for shared/js/github_issue.js.
 * Run: node tests/test_github_issue.js
 */
var assert = require('assert');
var path = require('path');
var g = require(path.join(__dirname, '..', 'shared', 'js', 'github_issue.js'));

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

t('keeps title and body', function () {
    var r = g.buildIssue(JSON.stringify({ title: 'Bug', body: 'Details' }));
    assert.deepStrictEqual(JSON.parse(r.json), { title: 'Bug', body: 'Details' });
});

t('drops every field outside the allowlist', function () {
    var r = g.buildIssue(JSON.stringify({
        title: 'T', body: 'B',
        assignees: ['someone'], labels: ['urgent'], milestone: 3, state: 'closed'
    }));
    assert.deepStrictEqual(Object.keys(JSON.parse(r.json)).sort(), ['body', 'title']);
});

t('a quote in the title cannot break out of the JSON', function () {
    var nasty = 'he said "hi"';
    var r = g.buildIssue(JSON.stringify({ title: nasty }));
    assert.strictEqual(JSON.parse(r.json).title, nasty);   // round-trips intact
});

t('a title that looks like JSON cannot inject sibling fields', function () {
    var inject = 'x", "assignees": ["victim"], "z": "';
    var r = g.buildIssue(JSON.stringify({ title: inject }));
    var out = JSON.parse(r.json);
    assert.deepStrictEqual(Object.keys(out), ['title']);
    assert.strictEqual(out.title, inject);
});

t('backslashes and newlines survive escaping', function () {
    var s = 'line1\nline2\end\t"q"';
    var r = g.buildIssue(JSON.stringify({ title: 'T', body: s }));
    assert.strictEqual(JSON.parse(r.json).body, s);
});

t('rejects a missing title', function () {
    assert.strictEqual(g.buildIssue(JSON.stringify({ body: 'b' })).error, 'missing_title');
});

t('rejects a whitespace-only title', function () {
    assert.strictEqual(g.buildIssue(JSON.stringify({ title: '   ' })).error, 'missing_title');
});

t('rejects a non-string title', function () {
    assert.strictEqual(g.buildIssue(JSON.stringify({ title: { a: 1 } })).error, 'missing_title');
    assert.strictEqual(g.buildIssue(JSON.stringify({ title: 42 })).error, 'missing_title');
});

t('rejects an unparseable body', function () {
    assert.strictEqual(g.buildIssue('not json at all').error, 'unparseable');
    assert.strictEqual(g.buildIssue('').error, 'unparseable');
});

t('rejects a top-level array', function () {
    assert.strictEqual(g.buildIssue('[{"title":"t"}]').error, 'not_an_object');
});

t('rejects an over-long title', function () {
    var long = new Array(g.MAX_TITLE + 2).join('a') + 'aa';
    assert.strictEqual(g.buildIssue(JSON.stringify({ title: long })).error, 'title_too_long');
});

t('truncates an over-long body instead of rejecting it', function () {
    var long = new Array(g.MAX_BODY + 100).join('b');
    var r = g.buildIssue(JSON.stringify({ title: 'T', body: long }));
    assert.strictEqual(JSON.parse(r.json).body.length, g.MAX_BODY);
});

t('omits body entirely when it is not a string', function () {
    var r = g.buildIssue(JSON.stringify({ title: 'T', body: { a: 1 } }));
    assert.deepStrictEqual(JSON.parse(r.json), { title: 'T' });
});

console.log(failures === 0 ? 'github_issue.js: all tests passed' : 'github_issue.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
