/*
 * Unit tests for shared/js/llm_guard.js.
 * Run: node tests/test_llm_guard.js
 */
var assert = require('assert');
var path = require('path');
var g = require(path.join(__dirname, '..', 'shared', 'js', 'llm_guard.js'));

var ALLOWED = 'meta-llama/llama-3.2-3b-instruct:free, mistralai/mistral-7b-instruct:free';
var OK_MODEL = 'meta-llama/llama-3.2-3b-instruct:free';

function body(extra) {
    var b = { model: OK_MODEL, messages: [{ role: 'user', content: 'hi' }] };
    for (var k in extra) { if (extra.hasOwnProperty(k)) { b[k] = extra[k]; } }
    return JSON.stringify(b);
}

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

/* ---- model allowlist ---- */

t('allows a model on the list', function () {
    var r = g.guard(body(), ALLOWED, '256');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(JSON.parse(r.json).model, OK_MODEL);
});

t('tolerates whitespace around list entries', function () {
    assert.strictEqual(g.guard(body(), '  ' + OK_MODEL + '  ,x', '256').error, undefined);
});

t('denies a model that is not on the list', function () {
    var r = g.guard(JSON.stringify({ model: 'openai/gpt-4o', messages: [] }), ALLOWED, '256');
    assert.strictEqual(r.error, 'model_denied');
});

t('fails closed when the allowlist is unset', function () {
    assert.strictEqual(g.guard(body(), undefined, '256').error, 'model_denied');
    assert.strictEqual(g.guard(body(), null, '256').error, 'model_denied');
    assert.strictEqual(g.guard(body(), '', '256').error, 'model_denied');
    assert.strictEqual(g.guard(body(), '  ,  ,', '256').error, 'model_denied');
});

t('matches the model exactly, not by prefix or substring', function () {
    assert.strictEqual(g.guard(JSON.stringify({ model: 'meta-llama/llama-3.2-3b-instruct' }), ALLOWED, '256').error, 'model_denied');
    assert.strictEqual(g.guard(JSON.stringify({ model: OK_MODEL + '-evil' }), ALLOWED, '256').error, 'model_denied');
});

t('rejects a missing or non-string model', function () {
    assert.strictEqual(g.guard(JSON.stringify({ messages: [] }), ALLOWED, '256').error, 'missing_model');
    assert.strictEqual(g.guard(JSON.stringify({ model: 42 }), ALLOWED, '256').error, 'missing_model');
    assert.strictEqual(g.guard(JSON.stringify({ model: '' }), ALLOWED, '256').error, 'missing_model');
});

t('a denial never reveals the allowlist, and never a rebuilt body', function () {
    var r = g.guard(JSON.stringify({ model: 'openai/gpt-4o' }), ALLOWED, '256');
    // The allowlist is the gateway's policy, not the caller's business: naming
    // the models it *would* have accepted turns every refusal into one round of
    // a guessing game the caller is meant to lose.
    assert.strictEqual(JSON.stringify(r).indexOf(OK_MODEL), -1);
    // And nothing that a downstream step could mistake for an approved body.
    assert.strictEqual(r.json, undefined);
    assert.strictEqual(r.max_tokens, undefined);
});

t('a denial says which model was asked for', function () {
    // Returned for the audit, not for the caller. A refusal record that cannot
    // name the model reduces to "somebody was refused something", and the alarm
    // on refused model requests exists precisely to show which model an agent
    // kept reaching for. The proxy sets llm.requested_model from this.
    var r = g.guard(JSON.stringify({ model: 'openai/gpt-4o' }), ALLOWED, '256');
    assert.strictEqual(r.error, 'model_denied');
    assert.strictEqual(r.model, 'openai/gpt-4o');

    var s = g.guard(JSON.stringify({ model: OK_MODEL, stream: true }), ALLOWED, '256');
    assert.strictEqual(s.error, 'stream_unsupported');
    assert.strictEqual(s.model, OK_MODEL);

    // Nothing to name when the body never carried one, and inventing a value
    // would be worse than the gap it fills.
    assert.strictEqual(g.guard(JSON.stringify({ messages: [] }), ALLOWED, '256').model, undefined);
    assert.strictEqual(g.guard('{', ALLOWED, '256').model, undefined);
});

/* ---- token ceiling ---- */

t('clamps max_tokens down to the cap', function () {
    assert.strictEqual(JSON.parse(g.guard(body({ max_tokens: 999999 }), ALLOWED, '256').json).max_tokens, 256);
});

t('leaves a request under the cap alone', function () {
    assert.strictEqual(JSON.parse(g.guard(body({ max_tokens: 100 }), ALLOWED, '256').json).max_tokens, 100);
});

t('inserts the cap when the caller omitted max_tokens', function () {
    assert.strictEqual(JSON.parse(g.guard(body(), ALLOWED, '256').json).max_tokens, 256);
});

t('falls back to the default cap when the KVM entry is absent or junk', function () {
    assert.strictEqual(JSON.parse(g.guard(body(), ALLOWED, undefined).json).max_tokens, g.DEFAULT_MAX_TOKENS);
    assert.strictEqual(JSON.parse(g.guard(body(), ALLOWED, 'not-a-number').json).max_tokens, g.DEFAULT_MAX_TOKENS);
    assert.strictEqual(JSON.parse(g.guard(body(), ALLOWED, '0').json).max_tokens, g.DEFAULT_MAX_TOKENS);
    assert.strictEqual(JSON.parse(g.guard(body(), ALLOWED, '-5').json).max_tokens, g.DEFAULT_MAX_TOKENS);
});

t('a zero or negative max_tokens becomes the cap, not an unbounded request', function () {
    assert.strictEqual(JSON.parse(g.guard(body({ max_tokens: 0 }), ALLOWED, '256').json).max_tokens, 256);
    assert.strictEqual(JSON.parse(g.guard(body({ max_tokens: -1 }), ALLOWED, '256').json).max_tokens, 256);
});

/* ---- streaming ---- */

t('refuses stream: true', function () {
    assert.strictEqual(g.guard(body({ stream: true }), ALLOWED, '256').error, 'stream_unsupported');
});

t('allows stream: false and stream absent', function () {
    assert.strictEqual(g.guard(body({ stream: false }), ALLOWED, '256').error, undefined);
    assert.strictEqual(g.guard(body(), ALLOWED, '256').error, undefined);
});

t('refuses streaming before checking the model, so a denial cannot be probed by streaming', function () {
    var r = g.guard(JSON.stringify({ model: 'openai/gpt-4o', stream: true }), ALLOWED, '256');
    assert.strictEqual(r.error, 'stream_unsupported');
});

/* ---- routing overrides ---- */

t('strips every routing override', function () {
    var r = g.guard(body({
        provider: { order: ['Expensive'] },
        transforms: ['middle-out'],
        models: ['openai/gpt-4o'],
        route: 'fallback'
    }), ALLOWED, '256');
    var out = JSON.parse(r.json);
    for (var i = 0; i < g.ROUTING_FIELDS.length; i++) {
        assert.ok(!(g.ROUTING_FIELDS[i] in out), g.ROUTING_FIELDS[i] + ' survived');
    }
});

t('the fallback models array cannot smuggle a denied model past the allowlist', function () {
    var out = JSON.parse(g.guard(body({ models: ['openai/gpt-4o'] }), ALLOWED, '256').json);
    assert.strictEqual(out.models, undefined);
    assert.strictEqual(out.model, OK_MODEL);
});

/* ---- pass-through of everything else ---- */

t('preserves messages verbatim', function () {
    var msgs = [{ role: 'system', content: 'be brief' }, { role: 'user', content: 'why is the sky "blue"?\n' }];
    var out = JSON.parse(g.guard(JSON.stringify({ model: OK_MODEL, messages: msgs }), ALLOWED, '256').json);
    assert.deepStrictEqual(out.messages, msgs);
});

t('leaves unrelated OpenAI fields alone', function () {
    var out = JSON.parse(g.guard(body({ temperature: 0.2, seed: 7, response_format: { type: 'json_object' } }), ALLOWED, '256').json);
    assert.strictEqual(out.temperature, 0.2);
    assert.strictEqual(out.seed, 7);
    assert.deepStrictEqual(out.response_format, { type: 'json_object' });
});

t('a prompt containing SQL is not the guard business -- it passes through', function () {
    var out = JSON.parse(g.guard(JSON.stringify({
        model: OK_MODEL,
        messages: [{ role: 'user', content: 'explain what UNION SELECT does' }]
    }), ALLOWED, '256').json);
    assert.strictEqual(out.messages[0].content, 'explain what UNION SELECT does');
});

/* ---- malformed input ---- */

t('rejects an unparseable body', function () {
    assert.strictEqual(g.guard('not json at all', ALLOWED, '256').error, 'unparseable');
    assert.strictEqual(g.guard('', ALLOWED, '256').error, 'unparseable');
});

t('rejects a top-level array', function () {
    assert.strictEqual(g.guard('[{"model":"x"}]', ALLOWED, '256').error, 'not_an_object');
});

t('rejects a JSON null body', function () {
    assert.strictEqual(g.guard('null', ALLOWED, '256').error, 'not_an_object');
});

console.log(failures === 0 ? 'llm_guard.js: all tests passed' : 'llm_guard.js: ' + failures + ' failed');
process.exit(failures === 0 ? 0 : 1);
