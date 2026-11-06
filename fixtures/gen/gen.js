// Emits [{ codec, hex, value }] cases encoded by the npm reference codecs.
// Buffers in `value` are hex strings; Uint32Arrays are plain number arrays.
const c = require('compact-encoding')
const m = require('hypercore/lib/messages')
const Protomux = require('protomux')

let seed = 0x9e3779b9
function rand() {
  // mulberry32: deterministic so the fixtures are reproducible
  seed = (seed + 0x6d2b79f5) | 0
  let t = seed
  t = Math.imul(t ^ (t >>> 15), t | 1)
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}
const int = (n) => Math.floor(rand() * n)
const bytes = (n) => Buffer.from(Array.from({ length: n }, () => int(256)))
const pick = (a) => a[int(a.length)]

const cases = []
function add(codec, enc, value) {
  cases.push({ codec, hex: Buffer.from(c.encode(enc, value)).toString('hex'), value: c.decode(enc, c.encode(enc, value)) })
}

const uintEdges = [0, 1, 0xfc, 0xfd, 0xfe, 0xff, 0xffff, 0x10000, 0xffffffff, 0x100000000, 2 ** 53 - 1]
for (const n of uintEdges) add('uint', c.uint, n)
for (let i = 0; i < 20; i++) add('uint', c.uint, int(2 ** int(53)))

const widths = { uint8: 8, uint16: 16, uint24: 24, uint32: 32, uint32be: 32, uint40: 40, uint48: 48, uint56: 53, uint64: 53, uint64be: 53 }
for (const [name, bits] of Object.entries(widths)) {
  for (const n of [0, 1, 2 ** bits - 1, Math.floor(2 ** bits / 3)]) add(name, c[name], n)
}

for (const n of [0, -1, 1, -2, 2, 126, -127, 2 ** 51, -(2 ** 52), 2 ** 52 - 1]) add('int', c.int, n)
for (const n of [0, -1, 1, 63, -64]) add('int8', c.int8, n)
for (const n of [0, -1, 32767, -32768]) add('int16', c.int16, n)
for (const n of [0, -1, 2147483647, -2147483648]) add('int32', c.int32, n)
for (const n of [0, -1, 2 ** 52 - 1, -(2 ** 52)]) add('int64', c.int64, n)

for (const n of [0, 1.5, -0.25, 3.4028234663852886e38, 1e-10]) add('float32', c.float32, n)
for (const n of [0, 1.5, -0.25, Math.PI, 1e300, -5e-324]) add('float64', c.float64, n)

add('bool', c.bool, true)
add('bool', c.bool, false)

for (const n of [0, 1, 252, 253, 300, 70000]) add('buffer', c.buffer, bytes(n))
add('optionalBuffer', c.optionalBuffer, null)
add('optionalBuffer', c.optionalBuffer, bytes(9))
for (const n of [0, 5, 400]) add('raw', c.raw, bytes(n))

for (const s of ['', 'hello', 'héllo wörld 🚀', 'x'.repeat(300), 'αβγ'.repeat(40)]) add('string', c.string, s)

add('fixed32', c.fixed32, bytes(32))
add('fixed64', c.fixed64, bytes(64))

for (const n of [0, 1, 7, 300]) add('uint32array', c.uint32array, new Uint32Array(Array.from({ length: n }, () => int(2 ** 32))))
for (const n of [0, 1, 8, 9, 70]) add('bitarray', c.bitarray, Array.from({ length: n }, () => rand() < 0.5))
add('array(uint)', c.array(c.uint), [0, 300, 70000, 2 ** 40])
add('array(string)', c.array(c.string), ['a', '', 'bcd'])
add('frame(string)', c.frame(c.string), 'framed')
add('frame(uint)', c.frame(c.uint), 0x123456)

for (const ip of ['127.0.0.1', '255.255.255.255', '10.0.40.100']) {
  add('ipv4', c.ipv4, ip)
  add('ip', c.ip, ip)
  add('ipAddress', c.ipAddress, { host: ip, port: int(65536) })
}
for (const ip of ['1:2:3:4:5:6:7:8', 'fe80::1', '::1', '2001:db8::ff00:42:8329']) {
  add('ipv6', c.ipv6, ip)
  add('ip', c.ip, ip)
  add('ipAddress', c.ipAddress, { host: ip, port: int(65536) })
}

// Hypercore
const node = () => ({ index: int(2 ** int(40)), size: int(2 ** int(40)), hash: bytes(32) })
const nodes = (n) => Array.from({ length: n }, node)
const signer = () => ({ signature: 'ed25519', namespace: bytes(32), publicKey: bytes(32) })

const manifests = [
  { version: 0, hash: 'blake2b', allowPatch: false, quorum: 1, signers: [signer()], prologue: null },
  { version: 0, hash: 'blake2b', allowPatch: false, quorum: 0, signers: [], prologue: { hash: bytes(32), length: 0 } },
  { version: 0, hash: 'blake2b', allowPatch: true, quorum: 2, signers: [signer(), signer(), signer()], prologue: null },
  { version: 1, hash: 'blake2b', allowPatch: false, quorum: 1, signers: [signer()], prologue: null, linked: null, userData: null },
  { version: 1, hash: 'blake2b', allowPatch: true, quorum: 2, signers: [signer(), signer()], prologue: { hash: bytes(32), length: 300 }, linked: [bytes(32), bytes(32)], userData: bytes(20) },
  { version: 2, hash: 'blake2b', allowPatch: false, quorum: 0, signers: [], prologue: { hash: bytes(32), length: 5 }, linked: null, userData: null },
  { version: 3, hash: 'blake2b', allowPatch: false, quorum: 1, signers: [signer()], prologue: null, linked: [], userData: bytes(1) }
]
for (const v of manifests) add('manifest', m.manifest, v)

const w = m.wire
add('handshake', w.handshake, { seeks: true, capability: bytes(32) })
add('handshake', w.handshake, { seeks: false, capability: bytes(32) })

const requests = [
  { id: 1, fork: 0, block: { index: 5, nodes: 2 } },
  { id: 70000, fork: 3, hash: { index: 9, nodes: 0 }, manifest: true },
  { id: 2, fork: 0, seek: { bytes: 2 ** 33, padding: 8 }, upgrade: { start: 0, length: 100 } },
  { id: 3, fork: 1, block: { index: 1, nodes: 1 }, hash: { index: 2, nodes: 3 }, seek: { bytes: 7, padding: 0 }, upgrade: { start: 4, length: 5 }, manifest: true, priority: 2 },
  { id: 4, fork: 0, priority: 300 }
]
for (const v of requests) add('request', w.request, v)
add('cancel', w.cancel, { request: 99 })

const datas = [
  { request: 1, fork: 0, block: { index: 4, value: bytes(100), nodes: nodes(3) } },
  { request: 2, fork: 1, hash: { index: 8, nodes: nodes(2) }, seek: { bytes: 900, nodes: nodes(1) } },
  { request: 3, fork: 0, upgrade: { start: 0, length: 10, nodes: nodes(4), additionalNodes: nodes(1), signature: bytes(64) } },
  { request: 4, fork: 2, upgrade: { start: 3, length: 1, nodes: [], additionalNodes: [], signature: null }, manifest: manifests[0] },
  { request: 5, fork: 0, block: { index: 0, value: bytes(70000), nodes: [] }, manifest: manifests[4] }
]
for (const v of datas) add('data', w.data, v)

add('noData', w.noData, { request: 7, reason: 0 })
add('noData', w.noData, { request: 8, reason: 2 })
for (const any of [false, true]) {
  add('want', w.want, { start: 1024, length: 2048, any })
  add('unwant', w.unwant, { start: 0, length: 70000, any })
}
add('range', w.range, { drop: false, start: 10, length: 1 })
add('range', w.range, { drop: true, start: 0, length: 0 })
add('range', w.range, { drop: false, start: 5, length: 300 })
add('bitfield', w.bitfield, { start: 0, bitfield: new Uint32Array([0xffffffff, 0, 0x1234]) })
add('bitfield', w.bitfield, { start: 32768, bitfield: new Uint32Array(0) })
add('sync', w.sync, { fork: 0, length: 100, remoteLength: 50, canUpgrade: true, uploading: true, downloading: false, hasManifest: true, allowPush: false })
add('sync', w.sync, { fork: 2, length: 2 ** 40, remoteLength: 0, canUpgrade: false, uploading: false, downloading: true, hasManifest: false, allowPush: true })
add('reorgHint', w.reorgHint, { from: 1, to: 2, ancestors: 300 })
add('extension', w.extension, { name: 'peartube/ping', message: bytes(12) })
add('extension', w.extension, { name: '', message: bytes(0) })

const proof = () => ({ signer: int(4), signature: bytes(64), patch: int(3) })
add('multiSignature', m.multiSignature, { proofs: [proof(), proof()], patch: nodes(2) })
add('multiSignature', m.multiSignature, { proofs: [], patch: [] })
add('multiSignaturev0', m.multiSignaturev0, {
  proofs: [
    { signer: 0, signature: bytes(64), patch: null },
    { signer: 1, signature: bytes(64), patch: { start: 2, length: 3, nodes: [1, 2, 300] } }
  ],
  patch: nodes(1)
})

// Protomux control bodies, captured from a real Protomux instance.
const frames = []
const stream = { userData: null, on() {}, write(b) { frames.push(Buffer.from(b)); return true }, destroyed: false }
const mux = new Protomux(stream)
for (const [protocol, id, handshake] of [['hypercore/alpha', bytes(32), 'hs'], ['peartube/rpc', null, null], ['x', bytes(1), '']]) {
  const ch = mux.createChannel({ protocol, id, handshake: handshake === null ? null : c.string })
  ch.open(handshake)
  ch.close()
}
for (const f of frames) {
  const codec = f[1] === 1 ? 'protomuxOpen' : 'protomuxChannelRef'
  const body = f.subarray(2)
  const st = { start: 0, end: body.length, buffer: body }
  const value = f[1] === 1
    ? { localId: c.uint.decode(st), protocol: c.string.decode(st), id: c.optionalBuffer.decode(st), handshake: c.raw.decode(st) }
    : { id: c.uint.decode(st) }
  cases.push({ codec, hex: body.toString('hex'), value })
}

process.stdout.write(
  JSON.stringify(
    cases,
    (k, v) => {
      if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex')
      if (v instanceof Uint32Array) return Array.from(v)
      if (v instanceof Uint8Array) return Buffer.from(v).toString('hex')
      return v
    },
    1
  ) + '\n'
)
