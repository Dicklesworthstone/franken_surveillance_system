'use strict';
// Execute only the reference's message handler, with synthetic inputs and a
// fake scheduler/socket. No controller, camera, or reference module is started.
const fs = require('node:fs');
const vm = require('node:vm');
if (process.argv.length !== 3) throw Error('expected reference source');
const source = fs.readFileSync(process.argv[2], 'utf8');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const marker = input.mode === 'stream'
    ? "    startStream(mac, channel, destHost, destPort, videoCodec = 'h264', audioCodec = 'aac') {"
    : '    onMessage(session, m) {';
const start = source.indexOf(marker);
const end = source.indexOf('\n    /**', start);
if (start < 0 || end < 0 || source.indexOf(marker, start + marker.length) >= 0)
    throw Error('reference handler not found uniquely');
const scheduled = [];
const sandbox = {
    debug_1: { dbg() {} },
    setTimeout(fn) { scheduled.push(fn); return 1; },
    crypto_1: { default: { randomBytes: () => Buffer.from('0123456789abcdef', 'hex') } },
    Date,
};
if (input.mode === 'stream') {
    const audioStart = source.indexOf('function audioSerializerParameters(codec, streamName) {');
    const audioEnd = source.indexOf('\nfunction wsAccept', audioStart);
    if (audioStart < 0 || audioEnd < 0) throw Error('reference serializer helper missing');
    vm.runInNewContext(source.slice(audioStart, audioEnd) + '\nthis.audioSerializerParameters = audioSerializerParameters;', sandbox);
}
const methodName = input.mode === 'stream' ? 'startStream' : 'onMessage';
const method = vm.runInNewContext(`({${source.slice(start, end)}}).${methodName}`, sandbox);
const actions = [];
const session = {
    mac: '001122AABBCC',
    socket: { destroyed: false, writableEnded: false },
    send: (name, payload, expected = false, responseTo = 0) => {
        actions.push({ name, payload, expected, responseTo });
        return actions.length;
    },
};
const self = {
    pending: new Map(), sessions: new Map([[session.mac, session]]),
    controllerUuid: input.uuid,
    audioCodecs: new Map(),
    activeTracks() { return new Map([['video1', 'synthetic'], ['video3', 'synthetic']]); },
    clearHandshakeTimer() {}, emit() {}, log() {},
};
if (input.mode === 'stream')
    method.call(self, session.mac, 'video2', input.host, input.port, 'h264', 'aac');
else
    method.call(self, session, input.message);
for (const fn of scheduled) fn();
process.stdout.write(JSON.stringify(actions));
