const assert = require('assert');
const snmp = require('../');

// A table instance OID carries its row index in the components following the
// column number. For a non-implied OCTET STRING index that encoding is a length
// component followed by exactly that many byte components. An OID that claims a
// different length than it supplies, or that carries components beyond the ones
// the index accounts for, names no row at all - the agent must reject it rather
// than decode it to some other row's index. See issue #305.

const agentPort = 17705;
const baseOid = '1.3.6.1.4.1.8072.9997.1';
const valueColumnOid = baseOid + '.2';
const statusColumnOid = baseOid + '.3';

const compositeBaseOid = '1.3.6.1.4.1.8072.9997.2';
const compositeStatusColumnOid = compositeBaseOid + '.4';

describe('table index OID decoding', function () {

    let agent;
    let sessions;

    before(function () {
        agent = snmp.createAgent({ port: agentPort, disableAuthorization: true }, function () {});
        agent.getAuthorizer().addCommunity('public');

        // Indexed by a single non-implied OCTET STRING.
        agent.registerProvider({
            name: 'octetIndexTable',
            type: snmp.MibProviderType.Table,
            oid: baseOid,
            tableColumns: [
                { number: 1, name: 'oitIndex', type: snmp.ObjectType.OctetString,
                    maxAccess: snmp.MaxAccess['not-accessible'] },
                { number: 2, name: 'oitValue', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-create'], defVal: 7 },
                { number: 3, name: 'oitStatus', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-create'], rowStatus: true }
            ],
            tableIndex: [ { columnNumber: 1, type: snmp.ObjectType.OctetString } ]
        });

        // Indexed by an INTEGER followed by a non-implied OCTET STRING, so that
        // an over-long string index eats the component the integer needs.
        agent.registerProvider({
            name: 'compositeIndexTable',
            type: snmp.MibProviderType.Table,
            oid: compositeBaseOid,
            tableColumns: [
                { number: 1, name: 'citNumber', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['not-accessible'] },
                { number: 2, name: 'citName', type: snmp.ObjectType.OctetString,
                    maxAccess: snmp.MaxAccess['not-accessible'] },
                { number: 3, name: 'citValue', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-create'], defVal: 7 },
                { number: 4, name: 'citStatus', type: snmp.ObjectType.Integer,
                    maxAccess: snmp.MaxAccess['read-create'], rowStatus: true }
            ],
            tableIndex: [
                { columnNumber: 1, type: snmp.ObjectType.Integer },
                { columnNumber: 2, type: snmp.ObjectType.OctetString }
            ]
        });
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
        // Drop every row so each test starts from a known table state.
        ['octetIndexTable', 'compositeIndexTable'].forEach((table) => {
            const mib = agent.getMib();
            if (mib.providerNodes[table]) {
                mib.getTableCells(table, true, true).forEach((row) => mib.deleteTableRow(table, row[0]));
            }
        });
    });

    const createSession = () => {
        const session = snmp.createSession('127.0.0.1', 'public',
            { port: agentPort, version: snmp.Version2c, timeout: 2000, retries: 0 });
        sessions.push(session);
        return session;
    };

    // Resolves with the response varbind, whether or not it carries a varbind
    // error - the point of these tests is which varbind error comes back.
    const setRowStatus = (session, oid, value) => new Promise((resolve, reject) => {
        session.set([{ oid: oid, type: snmp.ObjectType.Integer, value: value }], (error, varbinds) => {
            if (error) {
                reject(error);
            } else {
                resolve(varbinds[0]);
            }
        });
    });

    const get = (session, oid) => new Promise((resolve, reject) => {
        session.get([oid], (error, varbinds) => {
            if (error) {
                reject(error);
            } else {
                resolve(varbinds[0]);
            }
        });
    });

    // getTableCells throws for a table that has never held a row, so tests that
    // need to observe "no row was created" seed a canonical row first and assert
    // it is still the only one. With includeInstances set, each row is the
    // decoded row index followed by the value of every accessible column; the
    // agent stores the requested action in the RowStatus column.
    const tableRows = (table) => agent.getMib().getTableCells(table, true, true);

    const createCanonicalRow = async (session) => {
        // Index "B" - one length component, one byte component.
        const varbind = await setRowStatus(session, statusColumnOid + '.1.66',
            snmp.RowStatus['createAndGo']);
        assert.ok(!snmp.isVarbindError(varbind), 'canonical SET should succeed');
        assert.deepEqual(tableRows('octetIndexTable'), [[['B'], 7, snmp.RowStatus['createAndGo']]]);
    };

    it('creates a row for a canonical index encoding', async function () {
        const session = createSession();
        await createCanonicalRow(session);
    });

    it('does not create a row when the index claims more bytes than it supplies',
        async function () {
            const session = createSession();
            await createCanonicalRow(session);

            // Claims 5 bytes, supplies 1. Previously this truncated to "A",
            // created a row at the truncated index, and still answered
            // NoSuchInstance for the requested OID.
            const varbind = await setRowStatus(session, statusColumnOid + '.5.65',
                snmp.RowStatus['createAndGo']);

            assert.equal(varbind.type, snmp.ObjectType.NoSuchInstance);
            assert.deepEqual(tableRows('octetIndexTable'),
                [[['B'], 7, snmp.RowStatus['createAndGo']]], 'no row should have been created');
        });

    it('does not create a row when the index carries trailing components',
        async function () {
            const session = createSession();
            await createCanonicalRow(session);

            // Claims 1 byte, supplies 3. Previously the trailing components were
            // silently discarded and the row was created at index "A".
            const varbind = await setRowStatus(session, statusColumnOid + '.1.65.66.67',
                snmp.RowStatus['createAndGo']);

            assert.equal(varbind.type, snmp.ObjectType.NoSuchInstance);
            assert.deepEqual(tableRows('octetIndexTable'),
                [[['B'], 7, snmp.RowStatus['createAndGo']]], 'no row should have been created');
        });

    it('does not create a row when a composite index part overruns the address',
        async function () {
            const session = createSession();

            // Canonical row first: integer 1, then string "A".
            const created = await setRowStatus(session, compositeStatusColumnOid + '.1.1.65',
                snmp.RowStatus['createAndGo']);
            assert.ok(!snmp.isVarbindError(created), 'canonical composite SET should succeed');
            assert.deepEqual(tableRows('compositeIndexTable'),
                [[[1, 'A'], 7, snmp.RowStatus['createAndGo']]]);

            // Integer 2, then a string claiming 5 bytes with only 1 left. The
            // string index previously truncated to "B", creating a second row at
            // index [2, "B"] while answering NoSuchInstance for the OID asked for.
            const varbind = await setRowStatus(session, compositeStatusColumnOid + '.2.5.66',
                snmp.RowStatus['createAndGo']);

            assert.equal(varbind.type, snmp.ObjectType.NoSuchInstance);
            assert.deepEqual(tableRows('compositeIndexTable'),
                [[[1, 'A'], 7, snmp.RowStatus['createAndGo']]], 'no row should have been created');
        });

    it('answers NoSuchInstance for a GET of a malformed index and stays responsive',
        async function () {
            const session = createSession();
            await createCanonicalRow(session);

            const malformed = await get(session, valueColumnOid + '.5.65');
            assert.equal(malformed.type, snmp.ObjectType.NoSuchInstance);

            // A malformed index must not throw out of the request handler.
            const canonical = await get(session, valueColumnOid + '.1.66');
            assert.ok(!snmp.isVarbindError(canonical));
            assert.equal(canonical.value, 7);
        });

    it('leaves an existing row alone when a malformed index is destroyed',
        async function () {
            const session = createSession();
            await createCanonicalRow(session);

            const varbind = await setRowStatus(session, statusColumnOid + '.1.66.67',
                snmp.RowStatus['destroy']);

            assert.equal(varbind.type, snmp.ObjectType.NoSuchInstance);
            assert.deepEqual(tableRows('octetIndexTable'),
                [[['B'], 7, snmp.RowStatus['createAndGo']]], 'the canonical row should survive');
        });
});
