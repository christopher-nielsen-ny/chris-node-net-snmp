const assert = require('assert');
const { performance } = require('perf_hooks');
const snmp = require('../');

const MAX_SIGNED_INT32 = 2147483647;
const USM_TIME_WINDOW_SECONDS = 150;

// A stand-in for a parsed Message, carrying only what the engine time methods
// read: the USM security parameters and whether the message was authenticated.
// The real Message.prototype.hasAuthentication returns a truthy number rather
// than a boolean, so this mirrors that. The end-to-end suite at the bottom of
// this file exercises the same code paths with real parsed messages.
const fakeMessage = (engineBoots, engineTime, authenticated) => ({
    msgSecurityParameters: {
        msgAuthoritativeEngineID: Buffer.from('8000B98380ABCDEF12345678', 'hex'),
        msgAuthoritativeEngineBoots: engineBoots,
        msgAuthoritativeEngineTime: engineTime
    },
    hasAuthentication: () => authenticated ? 1 : 0
});

// An SNMPv1 or v2c message has no USM security parameters at all.
const fakeCommunityMessage = () => ({
    hasAuthentication: () => undefined
});

describe('SNMPv3 authoritative engine time (RFC 3414)', function () {

    const user = {
        name: 'betty',
        level: snmp.SecurityLevel.authNoPriv,
        authProtocol: snmp.AuthProtocols.sha,
        authKey: 'illhavesomeauth'
    };

    let session;

    beforeEach(function () {
        session = snmp.createV3Session('127.0.0.1', user, { port: 16210 });
    });

    afterEach(function () {
        if (session) {
            session.close();
            session = null;
        }
    });

    // Pretend the current anchor was established `seconds` ago, without waiting.
    const rewindAnchor = (seconds) => {
        session.engineTimeReceivedAt -= seconds * 1000;
    };

    describe('setEngineTime - time window updates (section 3.2 step 7b(1))', function () {

        it('establishes a notion of time from the first authentic message', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));

            assert.strictEqual(session.engineTimeBoots, 3);
            assert.strictEqual(session.engineTimeBase, 5000);
            assert.strictEqual(session.latestReceivedEngineTime, 5000);
            assert.notStrictEqual(session.engineTimeReceivedAt, null);
        });

        it('ignores a message that was not authenticated', function () {
            session.setEngineTime(fakeMessage(3, 5000, false));

            assert.strictEqual(session.engineTimeBoots, null);
            assert.strictEqual(session.engineTimeBase, null);
            assert.strictEqual(session.latestReceivedEngineTime, null);
            assert.strictEqual(session.engineTimeReceivedAt, null);
        });

        it('ignores a message with no USM security parameters', function () {
            session.setEngineTime(fakeCommunityMessage());

            assert.strictEqual(session.engineTimeBoots, null);
            assert.strictEqual(session.engineTimeReceivedAt, null);
        });

        it('updates when engineBoots has increased', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));
            session.setEngineTime(fakeMessage(4, 20, true));

            assert.strictEqual(session.engineTimeBoots, 4);
            assert.strictEqual(session.engineTimeBase, 20);
            assert.strictEqual(session.latestReceivedEngineTime, 20);
        });

        it('ignores a message whose engineBoots has decreased', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));
            session.setEngineTime(fakeMessage(2, 900000, true));

            assert.strictEqual(session.engineTimeBoots, 3);
            assert.strictEqual(session.engineTimeBase, 5000);
        });

        it('updates when engineBoots is unchanged and engineTime has advanced', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));
            session.setEngineTime(fakeMessage(3, 5060, true));

            assert.strictEqual(session.engineTimeBoots, 3);
            assert.strictEqual(session.engineTimeBase, 5060);
            assert.strictEqual(session.latestReceivedEngineTime, 5060);
        });

        it('ignores a replay of the highest engineTime already received', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));
            const anchoredAt = session.engineTimeReceivedAt;

            session.setEngineTime(fakeMessage(3, 5000, true));

            assert.strictEqual(session.engineTimeBase, 5000);
            assert.strictEqual(session.engineTimeReceivedAt, anchoredAt);
        });

        it('ignores a replay of an engineTime below the highest already received', function () {
            session.setEngineTime(fakeMessage(3, 5000, true));
            session.setEngineTime(fakeMessage(3, 4000, true));

            assert.strictEqual(session.engineTimeBase, 5000);
            assert.strictEqual(session.latestReceivedEngineTime, 5000);
        });

        // Regression test: the comparison in section 3.2 step 7b(1) is against
        // latestReceivedEngineTime, not against the locally advanced notion of
        // snmpEngineTime. Comparing against the advanced notion would mean that
        // a local clock running ahead of the agent could never resynchronise,
        // leaving the session permanently outside the agent's time window.
        it('resynchronises downwards when the local clock has raced ahead of the agent', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));
            rewindAnchor(2000);
            assert.strictEqual(session.getEngineTime().engineTime, 3000);

            session.setEngineTime(fakeMessage(1, 1100, true));

            assert.strictEqual(session.engineTimeBase, 1100);
            assert.strictEqual(session.latestReceivedEngineTime, 1100);
            assert.strictEqual(session.getEngineTime().engineTime, 1100);
        });
    });

    describe('getEngineTime - local advancement (section 2.3)', function () {

        it('has no notion of time before any authentic message', function () {
            assert.strictEqual(session.getEngineTime(), null);
        });

        it('advances the notion of engineTime with the local clock', function () {
            session.setEngineTime(fakeMessage(2, 1000, true));
            rewindAnchor(75);

            const notion = session.getEngineTime();
            assert.strictEqual(notion.engineBoots, 2);
            assert.strictEqual(notion.engineTime, 1075);
        });

        it('does not advance engineBoots while engineTime is in range', function () {
            session.setEngineTime(fakeMessage(2, 1000, true));
            rewindAnchor(100000);

            assert.strictEqual(session.getEngineTime().engineBoots, 2);
        });

        it('uses a monotonic clock, so a system clock step cannot move it', function () {
            session.setEngineTime(fakeMessage(2, 1000, true));

            // engineTimeReceivedAt is a performance.now() reading, which is
            // unrelated to Date.now() and unaffected by system clock steps.
            assert.ok(Math.abs(session.engineTimeReceivedAt - performance.now()) < 1000);
            assert.ok(Math.abs(session.engineTimeReceivedAt - Date.now()) > 1000000);
        });

        // RFC 3414 section 2.2.2: when snmpEngineTime reaches its maximum value,
        // snmpEngineBoots is incremented and snmpEngineTime is reset to zero.
        it('rolls engineTime over and increments engineBoots at the 31-bit limit', function () {
            session.setEngineTime(fakeMessage(7, MAX_SIGNED_INT32 - 10, true));
            rewindAnchor(30);

            const notion = session.getEngineTime();
            assert.strictEqual(notion.engineBoots, 8);
            assert.strictEqual(notion.engineTime, 19);
            assert.ok(notion.engineTime >= 0 && notion.engineTime <= MAX_SIGNED_INT32);
        });

        it('emits the maximum engineTime rather than rolling over early', function () {
            session.setEngineTime(fakeMessage(7, MAX_SIGNED_INT32 - 10, true));
            rewindAnchor(10);

            const notion = session.getEngineTime();
            assert.strictEqual(notion.engineBoots, 7);
            assert.strictEqual(notion.engineTime, MAX_SIGNED_INT32);
        });

        it('latches engineBoots at its maximum value rather than wrapping', function () {
            session.setEngineTime(fakeMessage(MAX_SIGNED_INT32 - 1, 0, true));
            rewindAnchor((MAX_SIGNED_INT32 + 1) * 5);

            assert.strictEqual(session.getEngineTime().engineBoots, MAX_SIGNED_INT32);
        });
    });

    describe('isInTimeWindow - timeliness checks (section 3.2 step 7b(2))', function () {

        it('accepts a message when no notion of time has been established', function () {
            assert.strictEqual(session.isInTimeWindow(fakeMessage(1, 1000, true)), true);
        });

        it('accepts an unauthenticated message without checking the window', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));

            assert.strictEqual(session.isInTimeWindow(fakeMessage(1, 999999, false)), true);
        });

        it('accepts a message with no USM security parameters', function () {
            assert.strictEqual(session.isInTimeWindow(fakeCommunityMessage()), true);
        });

        it('accepts the message that just established the notion of time', function () {
            const message = fakeMessage(1, 1000, true);
            session.setEngineTime(message);

            assert.strictEqual(session.isInTimeWindow(message), true);
        });

        it('accepts a message inside the time window', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));

            assert.strictEqual(session.isInTimeWindow(fakeMessage(1, 900, true)), true);
        });

        it('accepts a message exactly at the edge of the time window', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));

            assert.strictEqual(
                session.isInTimeWindow(fakeMessage(1, 1000 - USM_TIME_WINDOW_SECONDS, true)), true);
        });

        it('rejects a message more than the time window behind our notion', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));

            assert.strictEqual(
                session.isInTimeWindow(fakeMessage(1, 1000 - USM_TIME_WINDOW_SECONDS - 1, true)),
                false);
        });

        it('rejects a message whose engineBoots disagrees with our notion', function () {
            session.setEngineTime(fakeMessage(5, 1000, true));

            assert.strictEqual(session.isInTimeWindow(fakeMessage(4, 1000, true)), false);
        });

        it('rejects every message once engineBoots has latched at its maximum', function () {
            session.setEngineTime(fakeMessage(MAX_SIGNED_INT32, 1000, true));

            assert.strictEqual(session.isInTimeWindow(fakeMessage(MAX_SIGNED_INT32, 1000, true)),
                false);
        });

        it('measures the window against the advanced notion, not the anchor', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));
            rewindAnchor(200);

            // Our notion is now 1200, so the original anchor value of 1000 has
            // fallen outside the window, while 1200 is at its centre.
            assert.strictEqual(session.isInTimeWindow(fakeMessage(1, 1000, true)), false);
            assert.strictEqual(session.isInTimeWindow(fakeMessage(1, 1200, true)), true);
        });
    });

    describe('advanceEngineTime - outgoing requests (section 2.3)', function () {

        it('does nothing when the session has no cached security parameters', function () {
            session.setEngineTime(fakeMessage(1, 1000, true));
            assert.strictEqual(session.msgSecurityParameters, undefined);

            session.advanceEngineTime();

            assert.strictEqual(session.msgSecurityParameters, undefined);
        });

        it('does nothing when no notion of time has been established', function () {
            session.msgSecurityParameters = {
                msgAuthoritativeEngineBoots: 0,
                msgAuthoritativeEngineTime: 0
            };

            session.advanceEngineTime();

            assert.strictEqual(session.msgSecurityParameters.msgAuthoritativeEngineBoots, 0);
            assert.strictEqual(session.msgSecurityParameters.msgAuthoritativeEngineTime, 0);
        });

        it('writes the advanced notion into the cached security parameters', function () {
            session.msgSecurityParameters = {
                msgAuthoritativeEngineBoots: 1,
                msgAuthoritativeEngineTime: 1000
            };
            session.setEngineTime(fakeMessage(1, 1000, true));
            rewindAnchor(600);

            session.advanceEngineTime();

            assert.strictEqual(session.msgSecurityParameters.msgAuthoritativeEngineBoots, 1);
            assert.strictEqual(session.msgSecurityParameters.msgAuthoritativeEngineTime, 1600);
        });

        it('carries the advanced engineTime on the outgoing request', function () {
            session.msgSecurityParameters = {
                msgAuthoritativeEngineID: Buffer.from('8000B98380ABCDEF12345678', 'hex'),
                msgAuthoritativeEngineBoots: 1,
                msgAuthoritativeEngineTime: 1000
            };
            session.setEngineTime(fakeMessage(1, 1000, true));
            rewindAnchor(420);

            let sent;
            session.send = (req) => { sent = req; };
            session.get(['1.3.6.1.2.1.1.1.0'], function () {});

            assert.ok(sent, 'a request should have been handed to send()');
            assert.strictEqual(sent.message.msgSecurityParameters.msgAuthoritativeEngineBoots, 1);
            assert.strictEqual(sent.message.msgSecurityParameters.msgAuthoritativeEngineTime, 1420);
        });
    });
});

// These tests drive a real agent over the loopback interface, so the engine
// time methods are fed genuine parsed and authenticated Messages rather than
// the stand-in above. They confirm the wiring in Session.onMsg as well as the
// assumption that Message.hasAuthentication distinguishes the authenticated
// GetResponse from the unauthenticated discovery Report.
describe('SNMPv3 authoritative engine time over the wire', function () {

    const agentPort = 16211;
    const engineID = '8000B98380DEADBEEF00000001';
    const sysDescrOid = '1.3.6.1.2.1.1.1.0';

    const authUser = {
        name: 'betty',
        level: snmp.SecurityLevel.authNoPriv,
        authProtocol: snmp.AuthProtocols.sha,
        authKey: 'illhavesomeauth'
    };

    const authPrivUser = {
        name: 'wilma',
        level: snmp.SecurityLevel.authPriv,
        authProtocol: snmp.AuthProtocols.sha,
        authKey: 'illhavesomeauth',
        privProtocol: snmp.PrivProtocols.aes,
        privKey: 'andsomepriv'
    };

    const noAuthUser = {
        name: 'fred',
        level: snmp.SecurityLevel.noAuthNoPriv
    };

    let agent;
    let sessions;

    // The agent echoes the request's engineBoots and engineTime back in its
    // response, so to model an authoritative engine with a clock of its own we
    // overwrite those values on the way out. Clearing the cached buffer makes
    // the message re-serialise and re-authenticate over the new values, so the
    // session receives a properly authenticated message throughout.
    let agentEngineBoots = null;
    let agentEngineTime = null;
    // Values used for the unauthenticated discovery Report only, so that tests
    // can tell which message a session actually synchronised from.
    let agentReportEngineBoots = null;
    let agentReportEngineTime = null;

    before(function () {
        agent = snmp.createAgent({ port: agentPort, engineID: engineID, disableAuthorization: false },
            function () {});
        const authorizer = agent.getAuthorizer();
        authorizer.addUser(authUser);
        authorizer.addUser(authPrivUser);
        authorizer.addUser(noAuthUser);
        agent.registerProvider({
            name: 'sysDescr',
            type: snmp.MibProviderType.Scalar,
            oid: '1.3.6.1.2.1.1.1',
            scalarType: snmp.ObjectType.OctetString,
            maxAccess: snmp.MaxAccess['read-only']
        });
        agent.getMib().setScalarValue('sysDescr', 'engine time test agent');

        const listenerSend = agent.listener.send.bind(agent.listener);
        agent.listener.send = function (message, rinfo, socket) {
            const isReport = message.pdu && message.pdu.type === snmp.PduType.Report;
            const boots = isReport && agentReportEngineBoots !== null
                ? agentReportEngineBoots
                : agentEngineBoots;
            const time = isReport && agentReportEngineTime !== null
                ? agentReportEngineTime
                : agentEngineTime;
            if (time !== null && message.msgSecurityParameters
                    && message.msgSecurityParameters.msgAuthoritativeEngineBoots !== undefined) {
                message.msgSecurityParameters.msgAuthoritativeEngineBoots = boots;
                message.msgSecurityParameters.msgAuthoritativeEngineTime = time;
                message.buffer = null;
            }
            return listenerSend(message, rinfo, socket);
        };
    });

    after(function (done) {
        agent.close(() => done());
    });

    beforeEach(function () {
        sessions = [];
        agentEngineBoots = null;
        agentEngineTime = null;
        agentReportEngineBoots = null;
        agentReportEngineTime = null;
    });

    afterEach(function () {
        sessions.forEach((s) => s.close());
        sessions = [];
    });

    const createSession = (user) => {
        const session = snmp.createV3Session('127.0.0.1', user,
            { port: agentPort, timeout: 2000, retries: 0 });
        sessions.push(session);
        return session;
    };

    const get = (session) => new Promise((resolve, reject) => {
        session.get([sysDescrOid], (error, varbinds) => {
            if (error) {
                reject(error);
            } else if (varbinds[0] instanceof Error) {
                reject(varbinds[0]);
            } else {
                resolve(varbinds);
            }
        });
    });

    it('synchronises from an authenticated GetResponse, not the discovery Report',
        async function () {
            agentEngineBoots = 12;
            agentEngineTime = 345678;
            // The discovery Report is not authenticated, so these values must be
            // ignored no matter how far ahead of the real engine time they are.
            agentReportEngineBoots = 99;
            agentReportEngineTime = MAX_SIGNED_INT32 - 1;

            const session = createSession(authUser);
            await get(session);

            assert.strictEqual(session.engineTimeBoots, 12);
            assert.strictEqual(session.engineTimeBase, 345678);
            assert.strictEqual(session.latestReceivedEngineTime, 345678);
        });

    it('synchronises over authPriv as well as authNoPriv', async function () {
        agentEngineBoots = 4;
        agentEngineTime = 99000;

        const session = createSession(authPrivUser);
        await get(session);

        assert.strictEqual(session.engineTimeBoots, 4);
        assert.strictEqual(session.engineTimeBase, 99000);
    });

    it('never synchronises for a noAuthNoPriv user, since no message is authentic',
        async function () {
            agentEngineBoots = 4;
            agentEngineTime = 99000;

            const session = createSession(noAuthUser);
            await get(session);

            assert.strictEqual(session.engineTimeBoots, null);
            assert.strictEqual(session.engineTimeReceivedAt, null);
        });

    it('sends an advanced engineTime on a later request', async function () {
        agentEngineBoots = 2;
        agentEngineTime = 1000;

        const session = createSession(authUser);
        await get(session);

        // Pretend 500 seconds have passed since the response arrived, and let
        // the agent's clock advance by the same amount.
        session.engineTimeReceivedAt -= 500 * 1000;
        agentEngineTime = 1500;

        const sent = [];
        const send = session.send.bind(session);
        session.send = function (req, noWait) {
            sent.push(req.message.msgSecurityParameters.msgAuthoritativeEngineTime);
            return send(req, noWait);
        };

        await get(session);

        assert.deepStrictEqual(sent, [1500]);
        assert.strictEqual(session.engineTimeBase, 1500);
    });

    it('tracks the agent across a reboot that resets its engineTime', async function () {
        agentEngineBoots = 2;
        agentEngineTime = 900000;

        const session = createSession(authUser);
        await get(session);
        assert.strictEqual(session.engineTimeBase, 900000);

        agentEngineBoots = 3;
        agentEngineTime = 12;
        await get(session);

        assert.strictEqual(session.engineTimeBoots, 3);
        assert.strictEqual(session.engineTimeBase, 12);
    });

    it('reports a response that falls outside the time window', async function () {
        agentEngineBoots = 2;
        agentEngineTime = 1000;

        const session = createSession(authUser);
        await get(session);

        // A response claiming an engineTime below the highest already received
        // cannot advance our notion of time, and is far enough behind it to be
        // outside the window - RFC 3414 section 3.2 step 7b(2) discards it.
        agentEngineTime = 1000 - 151;

        await assert.rejects(get(session), (error) => {
            assert.ok(error instanceof snmp.ResponseInvalidError, 'expected ResponseInvalidError');
            assert.strictEqual(error.code, snmp.ResponseInvalidCode.ENotInTimeWindow);
            return true;
        });

        // Our notion of the agent's time is left untouched by the discard.
        assert.strictEqual(session.engineTimeBoots, 2);
        assert.strictEqual(session.latestReceivedEngineTime, 1000);
    });

    it('still accepts a response that is only slightly out of order', async function () {
        agentEngineBoots = 2;
        agentEngineTime = 1000;

        const session = createSession(authUser);
        await get(session);

        agentEngineTime = 1000 - 20;
        const varbinds = await get(session);

        assert.strictEqual(varbinds[0].oid, sysDescrOid);
        assert.strictEqual(session.latestReceivedEngineTime, 1000);
    });
});
