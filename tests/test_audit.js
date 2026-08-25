/*
 * Unit tests for shared/js/audit.js.
 * Run: node tests/test_audit.js
 */
var assert = require('assert');
var path = require('path');
var a = require(path.join(__dirname, '..', 'shared', 'js', 'audit.js'));

var failures = 0;
function t(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

/* ---------------------------------------------------------------- classify */

t('classifies each weather path', function () {
    assert.strictEqual(a.classify('weather-v1', 'GET', '/forecast'), 'weather.forecast');
    assert.strictEqual(a.classify('weather-v1', 'GET', '/archive'), 'weather.archive');
    assert.strictEqual(a.classify('weather-v1', 'GET', '/selftest'), 'weather.selftest');
});

t('separates a github read from a github write', function () {
    assert.strictEqual(a.classify('github-v1', 'GET', '/repos/o/n/issues'), 'github.issues.list');
    assert.strictEqual(a.classify('github-v1', 'POST', '/repos/o/n/issues'), 'github.issues.create');
});

t('an unrecognised path is named unknown rather than guessed at', function () {
    // If a path ever reaches the target that the proxy did not intend to allow,
    // the audit must make it stand out instead of quietly filing it under a
    // legitimate-looking action.
    assert.strictEqual(a.classify('github-v1', 'GET', '/user'), 'github-v1.unknown');
    assert.strictEqual(a.classify('github-v1', 'GET', '/repos/o/n/issues/7/comments'), 'github-v1.unknown');
    assert.strictEqual(a.classify('weather-v1', 'GET', '/../forecast'), 'weather-v1.unknown');
    assert.strictEqual(a.classify('mystery-v9', 'GET', '/forecast'), 'mystery-v9.unknown');
});

/* ----------------------------------------------------------------- outcome */

t('outcome is a verdict, not a status restatement', function () {
    assert.strictEqual(a.outcomeFor(200), 'ok');
    assert.strictEqual(a.outcomeFor(201), 'ok');
    assert.strictEqual(a.outcomeFor(401), 'unauthenticated');
    assert.strictEqual(a.outcomeFor(403), 'denied');
    assert.strictEqual(a.outcomeFor(429), 'throttled');
    assert.strictEqual(a.outcomeFor(400), 'invalid');
    assert.strictEqual(a.outcomeFor(404), 'invalid');
    assert.strictEqual(a.outcomeFor(502), 'error');
});

t('a fault with no status is still recorded as a failure', function () {
    assert.strictEqual(a.outcomeFor('', 'steps.jsonthreatprotection.ExecutionFailed'), 'error');
    assert.strictEqual(a.outcomeFor('', null), 'unknown');
});

/* ------------------------------------------------------------ buildRecord */

t('a denied call is logged with the identity that was refused', function () {
    // The audit is worthless if refusals are not in it: "who tried" matters at
    // least as much as "who succeeded".
    var r = a.buildRecord({
        proxy: 'github-v1', verb: 'POST', path: '/repos/o/n/issues',
        status: 403, app: 'agent-reader', clientId: 'abc123'
    });
    assert.strictEqual(r.outcome, 'denied');
    assert.strictEqual(r.agent, 'agent-reader');
    assert.strictEqual(r.client_key_fp, a.fingerprint('abc123'));
    assert.strictEqual(r.action, 'github.issues.create');
});

t('the caller key is fingerprinted, never recorded', function () {
    // This is the regression guard for a real leak: the record used to carry
    // Apigee's client_id, which is the consumer key itself -- the exact string
    // the agent puts in x-api-key. Anyone who could read the audit log could
    // then authenticate as that agent, which inverts the point of having one.
    // Assembled rather than written out, for the same reason as the PAT fixture
    // below. This line held a live consumer key until the repo was about to be
    // published. The test never needed a real one: all it asserts is that the
    // string does not survive into the record, which any 48-character stand-in
    // proves just as well.
    var key = 'AIRLOCK' + 'FIXTURE' + new Array(35).join('z');
    var r = a.buildRecord({
        proxy: 'weather-v1', verb: 'GET', path: '/forecast',
        status: 200, app: 'agent-reader', clientId: key
    });
    var json = JSON.stringify(r);
    assert.strictEqual(json.indexOf(key), -1, 'the API key reached the record: ' + json);
    assert.ok(!('client_id' in r), 'client_id is the key; it must not be a field');
    assert.ok(/^[0-9a-f]{8}$/.test(r.client_key_fp), 'want 8 hex digits, got ' + r.client_key_fp);
    // Also not a prefix of it, which would be just as spendable in part.
    assert.strictEqual(key.indexOf(r.client_key_fp), -1);
});

t('the caller address survives the load balancer in front of the gateway', function () {
    // The regression this guards: the record used to take the raw header value,
    // and on a served request that came back as a Google front end rather than
    // the caller. "Which machine did this agent call from" is one of the two
    // questions an incident starts with, so a field that answers it correctly
    // only on refusals is not good enough.
    var chain = a.forwardedChain('203.0.113.9, 35.191.34.3, 198.51.100.5');
    assert.deepStrictEqual(chain, ['203.0.113.9', '35.191.34.3', '198.51.100.5']);
    // The bracketed form Apigee's .values accessor returns when the header
    // arrives more than once, quoting and all.
    assert.deepStrictEqual(a.forwardedChain('["10.0.0.1", "10.0.0.2"]'),
                           ['10.0.0.1', '10.0.0.2']);
    assert.deepStrictEqual(a.forwardedChain(''), []);
    assert.deepStrictEqual(a.forwardedChain(null), []);

    var r = a.buildRecord({
        proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        clientIp: chain[0], forwardedFor: chain
    });
    assert.strictEqual(r.client_ip, '203.0.113.9');
    // The chain is kept alongside it, because the first element is the one hop
    // a caller can write themselves; the rest is what Google actually added.
    assert.strictEqual(r.forwarded_for, '203.0.113.9, 35.191.34.3, 198.51.100.5');

    // Where the chain is read from matters as much as how it is parsed. The
    // audit builder runs in the response flow for a served request, and by then
    // request.header.x-forwarded-for describes Apigee's own call to the target:
    // reading it there attributed every served request to a Google front end.
    // AM-Capture-Caller snapshots the header before anything can rewrite it, and
    // the snapshot has to win over the live header wherever both exist.
    var live = {
        'airlock.xff': '["198.51.100.9", "198.51.100.5"]',
        'request.header.x-forwarded-for.values': '["35.191.35.33"]'
    };
    assert.deepStrictEqual(a.callerChain(function (n) { return live[n]; }),
                           ['198.51.100.9', '198.51.100.5']);
    // With no snapshot -- a fault raised before the inbound shared flow ran --
    // the live header is still the client's, so it is the right fallback.
    assert.deepStrictEqual(
        a.callerChain(function (n) {
            return n === 'request.header.x-forwarded-for' ? '203.0.113.4' : '';
        }),
        ['203.0.113.4']);

    // A single hop is the whole story, so it is not repeated as a chain.
    var direct = a.buildRecord({
        proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        clientIp: '203.0.113.7', forwardedFor: ['203.0.113.7']
    });
    assert.strictEqual(direct.client_ip, '203.0.113.7');
    assert.ok(!('forwarded_for' in direct));
});

t('the fingerprint is stable per key and differs between keys', function () {
    // Both halves matter: stable, or records from one agent cannot be grouped;
    // distinct, or two agents are indistinguishable in the log.
    assert.strictEqual(a.fingerprint('key-one'), a.fingerprint('key-one'));
    assert.notStrictEqual(a.fingerprint('key-one'), a.fingerprint('key-two'));
    assert.strictEqual(a.fingerprint(''), null);
    assert.strictEqual(a.fingerprint(null), null);
    // Long, high-entropy inputs must not collapse onto each other.
    var seen = {}, i, fp;
    for (i = 0; i < 500; i++) {
        fp = a.fingerprint('8MilZG4HQQy2nSNzelg0uqXIjratYdrtWJSZ8ajSvmpJ' + i);
        assert.ok(!seen[fp], 'fingerprint collision at i=' + i);
        seen[fp] = true;
    }
});

t('a call with no verified identity is labelled, not left blank', function () {
    var r = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 401 });
    assert.strictEqual(r.agent, 'unauthenticated');
});

t('an agent refused at its scope is still named', function () {
    // The refusal that matters most is the one where a known agent reaches past
    // what it was granted -- and it was the one record that lost the name. Apigee
    // raises InvalidApiKeyForGivenResource from inside VerifyAPIKey and publishes
    // no identity at all, so both of the usual variables come back empty and the
    // record read "unauthenticated" for a caller the gateway had recognised
    // perfectly well. AE-Resolve-App looks the app up from the key itself, and
    // that lookup has to be allowed to answer when the other two cannot.
    var scoped = { 'airlock.app_name': 'agent-reader' };
    assert.strictEqual(a.callerName(function (n) { return scoped[n]; }), 'agent-reader');
    assert.strictEqual(
        a.buildRecord({ app: a.callerName(function (n) { return scoped[n]; }),
                        proxy: 'github-v1', verb: 'POST',
                        path: '/repos/o/r/issues', status: 403 }).agent,
        'agent-reader');

    // But it answers last. On a served request VerifyAPIKey has already resolved
    // the app, and that answer is the authoritative one; the lookup is a repair
    // for the fault path, not a second source of truth competing with it.
    var served = { 'developer.app.name': 'agent-operator', 'airlock.app_name': 'stale' };
    assert.strictEqual(a.callerName(function (n) { return served[n]; }), 'agent-operator');

    // And a key that resolves to no app at all is genuinely unattributed: the
    // lookup must not invent an identity for a caller who never had one.
    assert.strictEqual(a.callerName(function () { return ''; }), '');
    assert.strictEqual(
        a.buildRecord({ app: a.callerName(function () { return ''; }),
                        proxy: 'github-v1', verb: 'POST',
                        path: '/repos/o/r/issues', status: 403 }).agent,
        'unauthenticated');
});

t('a quote in an issue title cannot corrupt the record', function () {
    // The whole reason the record is built here instead of in a policy template.
    var nasty = 'fix "the thing" \ then {"injected":true}';
    var r = a.buildRecord({
        proxy: 'github-v1', verb: 'POST', path: '/repos/o/n/issues',
        status: 201, issueTitle: nasty
    });
    var round = JSON.parse(JSON.stringify(r));
    assert.strictEqual(round.detail, nasty);
});

t('an oversized title is truncated rather than logged whole', function () {
    var long = new Array(500).join('x');
    var r = a.buildRecord({
        proxy: 'github-v1', verb: 'POST', path: '/repos/o/n/issues',
        status: 201, issueTitle: long
    });
    assert.strictEqual(r.detail.length, a.MAX_DETAIL);
});

t('no response-derived field ever appears in the record', function () {
    // buildRecord is not given a response body at all, but assert on the output
    // keys so that adding one later trips a test rather than a code review.
    //
    // The fixture is assembled instead of written out. To be worth anything it
    // has to be shaped like a real classic PAT -- the prefix plus 36 characters
    // -- and a string shaped like a real credential is precisely what the M5
    // secret scan exists to find in a tracked file. The scan cannot tell a
    // convincing fixture from a pasted token and should not be taught to: the
    // fix is to keep the literal out of the file, not to widen the blind spot
    // that a real leak would then hide in.
    var pat = 'gh' + 'p_' + new Array(37).join('A');
    var r = a.buildRecord({
        proxy: 'github-v1', verb: 'GET', path: '/repos/o/n/issues',
        status: 200, repo: 'o/n', app: 'agent-reader',
        // Deliberately smuggled in; must be ignored.
        body: pat, response: { token: pat }
    });
    var keys = Object.keys(r).sort().join(',');
    assert.strictEqual(keys.indexOf('body'), -1, 'body leaked into the record');
    assert.strictEqual(keys.indexOf('response'), -1, 'response leaked into the record');
    assert.strictEqual(JSON.stringify(r).indexOf(pat.slice(0, 4)), -1, 'a token-shaped value reached the log');
});

t('weather records carry no github fields', function () {
    var r = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200 });
    assert.ok(!('repo' in r));
    assert.ok(!('detail' in r));
});

t('latency is a duration, and a nonsensical clock yields no number', function () {
    var ok = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        requestStart: '1000', responseEnd: '1180', targetStart: '1020', targetEnd: '1150' });
    assert.strictEqual(ok.latency_ms, 180);
    assert.strictEqual(ok.target_latency_ms, 130);

    var backwards = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        requestStart: '2000', responseEnd: '1000' });
    assert.ok(!('latency_ms' in backwards), 'a negative duration should be omitted, not logged');

    var missing = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200 });
    assert.ok(!('latency_ms' in missing));
});

t('empty and absent fields are dropped, not logged as null', function () {
    var r = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200 });
    var json = JSON.stringify(r);
    assert.strictEqual(json.indexOf('null'), -1, 'nulls survived into the record: ' + json);
});

/* ---------------------------------------------------------------------- llm */

t('separates a model call from model discovery', function () {
    assert.strictEqual(a.classify('llm-v1', 'POST', '/chat/completions'), 'llm.chat');
    assert.strictEqual(a.classify('llm-v1', 'GET', '/models'), 'llm.models');
    // The upstream's account endpoints are not proxied, and if one ever were the
    // audit must say so rather than file it under a familiar name.
    assert.strictEqual(a.classify('llm-v1', 'GET', '/credits'), 'llm-v1.unknown');
    assert.strictEqual(a.classify('llm-v1', 'GET', '/chat/completions'), 'llm-v1.unknown');
});

t('a served completion records the spend', function () {
    var r = a.buildRecord({ proxy: 'llm-v1', verb: 'POST', path: '/chat/completions', status: 200,
        app: 'agent-reader', model: 'z-ai/glm-5.2:free', requestedModel: 'z-ai/glm-5.2:free',
        promptTokens: '11', completionTokens: '42', totalTokens: '53' });
    assert.strictEqual(r.action, 'llm.chat');
    assert.strictEqual(r.model, 'z-ai/glm-5.2:free');
    assert.strictEqual(r.tokens_prompt, 11);
    assert.strictEqual(r.tokens_completion, 42);
    // A number, not the string Apigee handed over: a log-based metric summing
    // this field cannot add up quoted values.
    assert.strictEqual(r.tokens_total, 53);
    // Same model both ways, so naming it twice would add bytes and nothing else.
    assert.ok(!('requested_model' in r));
});

t('nothing that was said reaches the record', function () {
    // The property this whole file exists to keep true. Passing the text in
    // anyway is the test: buildRecord must ignore what it was not asked for
    // rather than depend on every caller having remembered to withhold it.
    var r = a.buildRecord({ proxy: 'llm-v1', verb: 'POST', path: '/chat/completions', status: 200,
        model: 'z-ai/glm-5.2:free', totalTokens: '53',
        messages: [{ role: 'user', content: 'my password is hunter2' }],
        completion: 'certainly, here it is' });
    var json = JSON.stringify(r);
    assert.strictEqual(json.indexOf('hunter2'), -1, 'prompt text reached the audit: ' + json);
    assert.strictEqual(json.indexOf('certainly'), -1, 'completion text reached the audit: ' + json);
    assert.ok(!('messages' in r) && !('completion' in r));
});

t('a refused model is still named, and claims no spend', function () {
    // A denial never reaches the upstream, so there is no served model and no
    // usage block. The requested model is then the only name in existence, and
    // it is the one an operator reading the refusal is looking for.
    var r = a.buildRecord({ proxy: 'llm-v1', verb: 'POST', path: '/chat/completions', status: 403,
        app: 'agent-reader', requestedModel: 'anthropic/claude-opus-4', faultName: 'model_denied' });
    assert.strictEqual(r.outcome, 'denied');
    assert.strictEqual(r.agent, 'agent-reader');
    assert.strictEqual(r.model, 'anthropic/claude-opus-4');
    assert.ok(!('tokens_total' in r), 'a refusal must not report a spend');
    assert.ok(!('tokens_prompt' in r) && !('tokens_completion' in r));
});

t('being answered by a different model than the one asked for is visible', function () {
    var r = a.buildRecord({ proxy: 'llm-v1', verb: 'POST', path: '/chat/completions', status: 200,
        model: 'z-ai/glm-5.2', requestedModel: 'z-ai/glm-5.2:free', totalTokens: '53' });
    assert.strictEqual(r.model, 'z-ai/glm-5.2');
    assert.strictEqual(r.requested_model, 'z-ai/glm-5.2:free');
});

t('the llm fields appear on no other proxy', function () {
    var r = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        model: 'z-ai/glm-5.2:free', totalTokens: '53' });
    assert.ok(!('model' in r) && !('tokens_total' in r));
});

/* -------------------------------------------------------------------- slack */

t('separates a slack read from a slack write', function () {
    assert.strictEqual(a.classify('slack-v1', 'GET', '/conversations.history'), 'slack.messages.read');
    assert.strictEqual(a.classify('slack-v1', 'POST', '/chat.postMessage'), 'slack.messages.post');
    assert.strictEqual(a.classify('slack-v1', 'GET', '/auth.test'), 'slack.auth.test');
});

t('a slack method the proxy does not route is named unknown', function () {
    // Slack's API is one flat namespace of ~200 methods, most of them writes.
    // If one ever reaches the target the audit must not file it under a
    // legitimate-looking action.
    assert.strictEqual(a.classify('slack-v1', 'POST', '/chat.delete'), 'slack-v1.unknown');
    assert.strictEqual(a.classify('slack-v1', 'GET', '/conversations.list'), 'slack-v1.unknown');
    assert.strictEqual(a.classify('slack-v1', 'GET', '/chat.postMessage'), 'slack-v1.unknown');
});

t('a posted message records who posted what, and where', function () {
    // An outbound write is the thing an audit exists to reconstruct, and
    // "agent-operator posted to C09ABCDEF" is only half an answer.
    var r = a.buildRecord({
        proxy: 'slack-v1', verb: 'POST', path: '/chat.postMessage', status: 200,
        app: 'agent-operator', channel: 'C09ABCDEF', messageText: 'deploy finished'
    });
    assert.strictEqual(r.action, 'slack.messages.post');
    assert.strictEqual(r.agent, 'agent-operator');
    assert.strictEqual(r.channel, 'C09ABCDEF');
    assert.strictEqual(r.detail, 'deploy finished');
});

t('a refused channel is named in the record even though it is not in the reply', function () {
    // The caller is told nothing about which channel it asked for -- that would
    // enumerate the allowlist. The audit reader is trusted, and the channel is
    // the only thing that makes the refusal actionable.
    var r = a.buildRecord({
        proxy: 'slack-v1', verb: 'GET', path: '/conversations.history', status: 403,
        app: 'agent-reader', channel: 'C0000000000'
    });
    assert.strictEqual(r.outcome, 'denied');
    assert.strictEqual(r.channel, 'C0000000000');
});

t('slack\'s own error string survives into the audit', function () {
    // slack_outcome.js rewrites 200+ok:false into a status and drops the string
    // from the response body. This record is the only place it still exists, and
    // it is what separates "the bot is not in that channel" from "the token lost
    // a scope" when someone reads the log six weeks later.
    var r = a.buildRecord({
        proxy: 'slack-v1', verb: 'POST', path: '/chat.postMessage', status: 403,
        app: 'agent-operator', channel: 'C09ABCDEF', slackError: 'not_in_channel'
    });
    assert.strictEqual(r.slack_error, 'not_in_channel');
});

t('a slack read carries no message text', function () {
    // conversations.history returns other people's messages. The audit records
    // that a read happened, never what was read.
    var r = a.buildRecord({
        proxy: 'slack-v1', verb: 'GET', path: '/conversations.history', status: 200,
        app: 'agent-reader', channel: 'C09ABCDEF', messageText: 'somebody else\'s message'
    });
    assert.ok(!('detail' in r), 'message text reached the audit on a read: ' + JSON.stringify(r));
});

t('an oversized message is truncated rather than logged whole', function () {
    var long = new Array(500).join('x');
    var r = a.buildRecord({
        proxy: 'slack-v1', verb: 'POST', path: '/chat.postMessage', status: 200,
        channel: 'C1', messageText: long
    });
    assert.strictEqual(r.detail.length, a.MAX_DETAIL);
});

t('the slack fields appear on no other proxy', function () {
    var r = a.buildRecord({ proxy: 'weather-v1', verb: 'GET', path: '/forecast', status: 200,
        channel: 'C09ABCDEF', slackError: 'not_in_channel' });
    assert.ok(!('channel' in r) && !('slack_error' in r));
});

console.log(failures === 0 ? 'audit.js: all tests passed' : 'audit.js: ' + failures + ' failure(s)');
process.exit(failures === 0 ? 0 : 1);
