// Pure-JS SHA-1 / SHA-256 and PBKDF2-HMAC. Used where WebCrypto can't help:
// - Cloudflare Workers reject PBKDF2 with more than 100,000 iterations, but Django hashes use 600k–1M+;
// - scrypt (no WebCrypto primitive) needs PBKDF2-HMAC-SHA256 with one iteration.
// The PBKDF2 loop precomputes the HMAC inner/outer states, so each iteration costs two compressions.

const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
])

interface HashSpec {
  /** digest length in 32-bit words */
  words: number
  init(): Int32Array
  compress(state: Int32Array, block: Int32Array, w: Int32Array): void
  scheduleLength: number
}

function sha256Compress(s: Int32Array, block: Int32Array, w: Int32Array): void {
  for (let i = 0; i < 16; i++) w[i] = block[i]
  for (let i = 16; i < 64; i++) {
    const x = w[i - 15]
    const y = w[i - 2]
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
  }
  let a = s[0]
  let b = s[1]
  let c = s[2]
  let d = s[3]
  let e = s[4]
  let f = s[5]
  let g = s[6]
  let h = s[7]
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
    const ch = (e & f) ^ (~e & g)
    const t1 = (h + S1 + ch + K256[i] + w[i]) | 0
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
    const maj = (a & b) ^ (a & c) ^ (b & c)
    const t2 = (S0 + maj) | 0
    h = g
    g = f
    f = e
    e = (d + t1) | 0
    d = c
    c = b
    b = a
    a = (t1 + t2) | 0
  }
  s[0] = (s[0] + a) | 0
  s[1] = (s[1] + b) | 0
  s[2] = (s[2] + c) | 0
  s[3] = (s[3] + d) | 0
  s[4] = (s[4] + e) | 0
  s[5] = (s[5] + f) | 0
  s[6] = (s[6] + g) | 0
  s[7] = (s[7] + h) | 0
}

function sha1Compress(s: Int32Array, block: Int32Array, w: Int32Array): void {
  for (let i = 0; i < 16; i++) w[i] = block[i]
  for (let i = 16; i < 80; i++) {
    const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
    w[i] = (x << 1) | (x >>> 31)
  }
  let a = s[0]
  let b = s[1]
  let c = s[2]
  let d = s[3]
  let e = s[4]
  for (let i = 0; i < 80; i++) {
    let f: number
    let k: number
    if (i < 20) {
      f = (b & c) | (~b & d)
      k = 0x5a827999
    } else if (i < 40) {
      f = b ^ c ^ d
      k = 0x6ed9eba1
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d)
      k = 0x8f1bbcdc
    } else {
      f = b ^ c ^ d
      k = 0xca62c1d6
    }
    const t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0
    e = d
    d = c
    c = (b << 30) | (b >>> 2)
    b = a
    a = t
  }
  s[0] = (s[0] + a) | 0
  s[1] = (s[1] + b) | 0
  s[2] = (s[2] + c) | 0
  s[3] = (s[3] + d) | 0
  s[4] = (s[4] + e) | 0
}

const SPECS: Record<'sha1' | 'sha256', HashSpec> = {
  sha256: {
    words: 8,
    scheduleLength: 64,
    init: () =>
      new Int32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
      ]),
    compress: sha256Compress,
  },
  sha1: {
    words: 5,
    scheduleLength: 80,
    init: () => new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]),
    compress: sha1Compress,
  },
}

/** Hash `data` starting from `state` that already absorbed `prefixLength` bytes (multiple of 64). */
function finish(spec: HashSpec, state: Int32Array, prefixLength: number, data: Uint8Array): Int32Array {
  const s = new Int32Array(state)
  const w = new Int32Array(spec.scheduleLength)
  const block = new Int32Array(16)
  const total = prefixLength + data.length
  const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64)
  padded.set(data)
  padded[data.length] = 0x80
  const bits = total * 8
  const view = new DataView(padded.buffer)
  view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000))
  view.setUint32(padded.length - 4, bits >>> 0)
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) block[i] = view.getInt32(off + i * 4)
    spec.compress(s, block, w)
  }
  return s
}

function wordsToBytes(words: Int32Array, out: Uint8Array, offset = 0, length = words.length * 4): void {
  for (let i = 0; i < length; i++) out[offset + i] = (words[i >> 2] >>> (24 - (i & 3) * 8)) & 0xff
}

/** One-shot SHA-1 / SHA-256 digest (pure JS). */
export function shaDigest(algorithm: 'sha1' | 'sha256', data: Uint8Array): Uint8Array {
  const spec = SPECS[algorithm]
  const out = new Uint8Array(spec.words * 4)
  wordsToBytes(finish(spec, spec.init(), 0, data), out)
  return out
}

/** PBKDF2-HMAC (pure JS, synchronous). */
export function pbkdf2Js(
  algorithm: 'sha1' | 'sha256',
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  const spec = SPECS[algorithm]
  const hLen = spec.words * 4
  let key = password
  if (key.length > 64) key = shaDigest(algorithm, key)
  const ipad = new Uint8Array(64).fill(0x36)
  const opad = new Uint8Array(64).fill(0x5c)
  for (let i = 0; i < key.length; i++) {
    ipad[i] ^= key[i]
    opad[i] ^= key[i]
  }
  const w = new Int32Array(spec.scheduleLength)
  const block = new Int32Array(16)
  const absorb = (bytes: Uint8Array): Int32Array => {
    const s = spec.init()
    const v = new DataView(bytes.buffer, bytes.byteOffset, 64)
    for (let i = 0; i < 16; i++) block[i] = v.getInt32(i * 4)
    spec.compress(s, block, w)
    return s
  }
  const inner = absorb(ipad)
  const outer = absorb(opad)

  // Reusable single-block messages for the iteration loop: digest words, 0x80, zeros, length (64 + hLen bytes).
  const innerBlock = new Int32Array(16)
  const outerBlock = new Int32Array(16)
  const lenBits = (64 + hLen) * 8
  for (const b of [innerBlock, outerBlock]) {
    b[spec.words] = 0x80000000 | 0
    b[15] = lenBits
  }
  const si = new Int32Array(spec.words)
  const so = new Int32Array(spec.words)

  const out = new Uint8Array(dkLen)
  const blocks = Math.ceil(dkLen / hLen)
  const saltBlock = new Uint8Array(salt.length + 4)
  saltBlock.set(salt)
  const acc = new Int32Array(spec.words)
  for (let blockIndex = 1; blockIndex <= blocks; blockIndex++) {
    saltBlock[salt.length] = (blockIndex >>> 24) & 0xff
    saltBlock[salt.length + 1] = (blockIndex >>> 16) & 0xff
    saltBlock[salt.length + 2] = (blockIndex >>> 8) & 0xff
    saltBlock[salt.length + 3] = blockIndex & 0xff
    // U1 = HMAC(P, S || INT(i))
    const u1Inner = finish(spec, inner, 64, saltBlock)
    const u1Bytes = new Uint8Array(hLen)
    wordsToBytes(u1Inner, u1Bytes)
    const u = finish(spec, outer, 64, u1Bytes)
    acc.set(u)
    for (let it = 1; it < iterations; it++) {
      for (let i = 0; i < spec.words; i++) innerBlock[i] = u[i]
      si.set(inner)
      spec.compress(si, innerBlock, w)
      for (let i = 0; i < spec.words; i++) outerBlock[i] = si[i]
      so.set(outer)
      spec.compress(so, outerBlock, w)
      for (let i = 0; i < spec.words; i++) {
        u[i] = so[i]
        acc[i] ^= so[i]
      }
    }
    const offset = (blockIndex - 1) * hLen
    wordsToBytes(acc, out, offset, Math.min(hLen, dkLen - offset))
  }
  return out
}
