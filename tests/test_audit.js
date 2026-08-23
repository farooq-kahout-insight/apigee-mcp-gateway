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
    var key = 'AIRLOCKFIXTUREzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';
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

console.log(failures === 0 ? 'audit.js: all tests passed' : 'audit.js: ' + failures + ' failure(s)');
process.exit(failures === 0 ? 0 : 1);
