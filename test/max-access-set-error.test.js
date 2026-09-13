const assert = require('assert');
const snmp = require('../');

// A SET aimed at an object whose MAX-ACCESS is below read-write must be
// refused with notWritable, not noAccess. RFC 3416 section 4.2.5 splits the
// two: rule (1) reserves noAccess for a variable denied because it is not in
// the requester's MIB view, and rule (2) gives notWritable for a variable that
// exists but cannot be modified whatever value is supplied.
//
// notWritable has no meaning to an SNMPv1 manager, whose error-status stops at
// genErr(5), so a response to a version 1 request is translated down using the
// table in RFC 2089 section 2.1 - notWritable becomes noSuchName. That matches
// RFC 1157 section 4.1.5 rule (1) directly. SNMPv1's readOnly(4) is never
// generated: see RFC 1908 section 3.1.2. See issue #306.

const agentPort = 17706;
const baseOid = '1.3.6.1.4.1.8072.9998';

const roScalarOid = baseOid + '.1.0';
const rwScalarOid = baseOid + '.2.0';
const naScalarOid = baseOid + '.3.0';
const errScalarOid = baseOid + '.4.0';

const tableOid = baseOid + '.5';
const roColumnOid = tableOid + '.2';
const rwColumnOid = tableOid + '.3';

describe('MAX-ACCESS set error status', function () {

    let agent;
    let sessions;

    before(function () {
        agent = snmp.createAgent({ port: agentPort, disableAuthorization: true }, function () {});
        agent.getAuthorizer().addCommunity('public');

        const scalar = (name, oid, maxAccess, handler) => {
            const provider = {
                name: name,
                type: snmp.MibProviderType.Scalar,
                oid: oid,
                scalarType: snmp.ObjectType.Integer,
                maxAccess: maxAccess
            };
            if (handler) {
                provider.handler = handler;
            }
            agent.registerProvider(provider);
        };

        scalar('roScalar', baseOid + '.1', snmp.MaxAccess['read-only']);
        scalar('rwScalar', baseOid + '.2', snmp.MaxAccess['read-write']);
        scalar('naScalar', baseOid + '.3', snmp.MaxAccess['not-accessible']);

        // Read-write, so the MAX-ACCESS gate lets the request through to the
        // handler, which then fails it with a status SNMPv1 already defines.
        scalar('errScalar', baseOid + '.4', snmp.MaxAccess['read-write'], function (mibRequest) {
            mibRequest.done({ errorStatus: snmp.ErrorStatus.GeneralError });
        });

        agent.registerProvider({
            name: 'accessTable',
            type: snmp.MibProviderType.Table,
            oid: tableOid,
            tableColumns: [
                { number: 1, name: 'atIndex', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['not-accessible'] },
                { number: 2, name: 'atReadOnly', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-only'] },
                { number: 3, name: 'atReadWrite', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-write'] }
            ],
            tableIndex: [ { columnNumber: 1, type: snmp.ObjectType.Integer } ]
        });

        const mib = agent.getMib();
        mib.setScalarValue('roScalar', 1);
        mib.setScalarValue('rwScalar', 1);
        mib.setScalarValue('naScalar', 1);
        mib.setScalarValue('errScalar', 1);
        mib.addTableRow('accessTable', [1, 10, 20]);
    });

    after(function (done) {
        agent.close(() => done());
    });

    beforeEach(function () {
        sessions = [];
    });

    afterEach(function () {
        sessions.forEach((s) => s.close());
        sessions = [];
    });

    const createSession = (version) => {
        const session = snmp.createSession('127.0.0.1', 'public',
            { port: agentPort, version: version, timeout: 2000, retries: 0 });
        sessions.push(session);
        return session;
    };

    // These requests are meant to fail at the PDU level, so resolve with the
    // error rather than the varbinds - the point of each test is which
    // error-status came back. A request that unexpectedly succeeds resolves
    // with null so the assertion reports that plainly.
    const set = (session, oid, value) => new Promise((resolve) => {
        session.set([{ oid: oid, type: snmp.ObjectType.Integer, value: value }],
            (error) => resolve(error));
    });

    const get = (session, oid) => new Promise((resolve) => {
        session.get([oid], (error, varbinds) => resolve(error || varbinds[0]));
    });

    it('answers notWritable for a v2c set of a read-only scalar', async function () {
        const error = await set(createSession(snmp.Version2c), roScalarOid, 2);
        assert.ok(error, 'set of a read-only scalar should fail');
        assert.equal(error.status, snmp.ErrorStatus.NotWritable);
        assert.equal(agent.getMib().getScalarValue('roScalar'), 1, 'value should be unchanged');
    });

    it('answers notWritable for a v2c set of a read-only table column', async function () {
        const error = await set(createSession(snmp.Version2c), roColumnOid + '.1', 99);
        assert.ok(error, 'set of a read-only column should fail');
        assert.equal(error.status, snmp.ErrorStatus.NotWritable);
    });

    it('answers notWritable for a v2c set of a not-accessible scalar', async function () {
        // Below read-write either way, so rule (2) applies here too - the
        // object is not in any MIB view, but it is still the write that is
        // being refused.
        const error = await set(createSession(snmp.Version2c), naScalarOid, 2);
        assert.ok(error, 'set of a not-accessible scalar should fail');
        assert.equal(error.status, snmp.ErrorStatus.NotWritable);
    });

    it('answers noSuchName for a v1 set of a read-only scalar', async function () {
        const error = await set(createSession(snmp.Version1), roScalarOid, 2);
        assert.ok(error, 'set of a read-only scalar should fail');
        assert.equal(error.status, snmp.ErrorStatus.NoSuchName);
    });

    it('allows a set of a read-write scalar', async function () {
        const error = await set(createSession(snmp.Version2c), rwScalarOid, 42);
        assert.ok(!error, 'set of a read-write scalar should succeed');
        assert.equal(agent.getMib().getScalarValue('rwScalar'), 42);
    });

    it('allows a set of a read-write table column', async function () {
        const error = await set(createSession(snmp.Version2c), rwColumnOid + '.1', 42);
        assert.ok(!error, 'set of a read-write column should succeed');
    });

    it('still answers noAccess for a v2c get below read-only', async function () {
        // Reads keep the existing behaviour: the set fix must not drag the
        // get path along with it.
        const result = await get(createSession(snmp.Version2c), naScalarOid);
        assert.ok(result instanceof Error, 'get of a not-accessible scalar should fail');
        assert.equal(result.status, snmp.ErrorStatus.NoAccess);
    });

    it('maps noAccess to noSuchName for a v1 get below read-only', async function () {
        const result = await get(createSession(snmp.Version1), naScalarOid);
        assert.ok(result instanceof Error, 'get of a not-accessible scalar should fail');
        assert.equal(result.status, snmp.ErrorStatus.NoSuchName);
    });

    it('leaves an error status SNMPv1 already defines untranslated', async function () {
        const v2cError = await set(createSession(snmp.Version2c), errScalarOid, 2);
        assert.ok(v2cError);
        assert.equal(v2cError.status, snmp.ErrorStatus.GeneralError);

        const v1Error = await set(createSession(snmp.Version1), errScalarOid, 2);
        assert.ok(v1Error);
        assert.equal(v1Error.status, snmp.ErrorStatus.GeneralError);
    });
});
