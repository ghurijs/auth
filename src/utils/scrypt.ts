// scrypt (RFC 7914) in pure JS — WebCrypto has no scrypt primitive. Compatible with Python's hashlib.scrypt.
import { pbkdf2Js } from './sha'

function salsa208(b: Uint32Array, x: Uint32Array): void {
  x.set(b)
  for (let i = 0; i < 8; i += 2) {
    let t: number
    t = (x[0] + x[12]) | 0
    x[4] ^= (t << 7) | (t >>> 25)
    t = (x[4] + x[0]) | 0
    x[8] ^= (t << 9) | (t >>> 23)
    t = (x[8] + x[4]) | 0
    x[12] ^= (t << 13) | (t >>> 19)
    t = (x[12] + x[8]) | 0
    x[0] ^= (t << 18) | (t >>> 14)
    t = (x[5] + x[1]) | 0
    x[9] ^= (t << 7) | (t >>> 25)
    t = (x[9] + x[5]) | 0
    x[13] ^= (t << 9) | (t >>> 23)
    t = (x[13] + x[9]) | 0
    x[1] ^= (t << 13) | (t >>> 19)
    t = (x[1] + x[13]) | 0
    x[5] ^= (t << 18) | (t >>> 14)
    t = (x[10] + x[6]) | 0
    x[14] ^= (t << 7) | (t >>> 25)
    t = (x[14] + x[10]) | 0
    x[2] ^= (t << 9) | (t >>> 23)
    t = (x[2] + x[14]) | 0
    x[6] ^= (t << 13) | (t >>> 19)
    t = (x[6] + x[2]) | 0
    x[10] ^= (t << 18) | (t >>> 14)
    t = (x[15] + x[11]) | 0
    x[3] ^= (t << 7) | (t >>> 25)
    t = (x[3] + x[15]) | 0
    x[7] ^= (t << 9) | (t >>> 23)
    t = (x[7] + x[3]) | 0
    x[11] ^= (t << 13) | (t >>> 19)
    t = (x[11] + x[7]) | 0
    x[15] ^= (t << 18) | (t >>> 14)
    t = (x[0] + x[3]) | 0
    x[1] ^= (t << 7) | (t >>> 25)
    t = (x[1] + x[0]) | 0
    x[2] ^= (t << 9) | (t >>> 23)
    t = (x[2] + x[1]) | 0
    x[3] ^= (t << 13) | (t >>> 19)
    t = (x[3] + x[2]) | 0
    x[0] ^= (t << 18) | (t >>> 14)
    t = (x[5] + x[4]) | 0
    x[6] ^= (t << 7) | (t >>> 25)
    t = (x[6] + x[5]) | 0
    x[7] ^= (t << 9) | (t >>> 23)
    t = (x[7] + x[6]) | 0
    x[4] ^= (t << 13) | (t >>> 19)
    t = (x[4] + x[7]) | 0
    x[5] ^= (t << 18) | (t >>> 14)
    t = (x[10] + x[9]) | 0
    x[11] ^= (t << 7) | (t >>> 25)
    t = (x[11] + x[10]) | 0
    x[8] ^= (t << 9) | (t >>> 23)
    t = (x[8] + x[11]) | 0
    x[9] ^= (t << 13) | (t >>> 19)
    t = (x[9] + x[8]) | 0
    x[10] ^= (t << 18) | (t >>> 14)
    t = (x[15] + x[14]) | 0
    x[12] ^= (t << 7) | (t >>> 25)
    t = (x[12] + x[15]) | 0
    x[13] ^= (t << 9) | (t >>> 23)
    t = (x[13] + x[12]) | 0
    x[14] ^= (t << 13) | (t >>> 19)
    t = (x[14] + x[13]) | 0
    x[15] ^= (t << 18) | (t >>> 14)
  }
  for (let i = 0; i < 16; i++) b[i] = (b[i] + x[i]) | 0
}

/** BlockMix: `b` (32r words) → `y` scratch; result written back into `b`. */
function blockMix(b: Uint32Array, y: Uint32Array, r: number, x: Uint32Array, tmp: Uint32Array): void {
  x.set(b.subarray((2 * r - 1) * 16, 2 * r * 16))
  for (let i = 0; i < 2 * r; i++) {
    for (let j = 0; j < 16; j++) x[j] ^= b[i * 16 + j]
    salsa208(x, tmp)
    // even blocks first, then odd blocks
    const dest = (i & 1 ? r + (i >> 1) : i >> 1) * 16
    y.set(x, dest)
  }
  b.set(y)
}

export interface ScryptParams {
  N: number
  r: number
  p: number
  dkLen: number
  /** Max memory in bytes (default 64 MiB, like Django). */
  maxmem?: number
}

/** scrypt key derivation. */
export function scrypt(password: Uint8Array, salt: Uint8Array, params: ScryptParams): Uint8Array {
  const { N, r, p, dkLen } = params
  if (N < 2 || (N & (N - 1)) !== 0) throw new RangeError('scrypt: N must be a power of 2 greater than 1')
  if (r < 1 || p < 1) throw new RangeError('scrypt: r and p must be positive')
  const maxmem = params.maxmem ?? 64 * 1024 * 1024
  const need = 128 * r * N + 128 * r * p + 256 * r
  if (need > maxmem) throw new RangeError(`scrypt: memory limit exceeded (${need} > ${maxmem})`)
  const blockWords = 32 * r
  const B = pbkdf2Js('sha256', password, salt, 1, p * 128 * r)
  const words = new Uint32Array(p * blockWords)
  for (let i = 0; i < words.length; i++) {
    const o = i * 4
    words[i] = B[o] | (B[o + 1] << 8) | (B[o + 2] << 16) | (B[o + 3] << 24)
  }
  const V = new Uint32Array(N * blockWords)
  const X = new Uint32Array(blockWords)
  const Y = new Uint32Array(blockWords)
  const x16 = new Uint32Array(16)
  const tmp16 = new Uint32Array(16)
  for (let block = 0; block < p; block++) {
    const off = block * blockWords
    X.set(words.subarray(off, off + blockWords))
    for (let i = 0; i < N; i++) {
      V.set(X, i * blockWords)
      blockMix(X, Y, r, x16, tmp16)
    }
    for (let i = 0; i < N; i++) {
      const j = X[(2 * r - 1) * 16] & (N - 1)
      const vo = j * blockWords
      for (let k = 0; k < blockWords; k++) X[k] ^= V[vo + k]
      blockMix(X, Y, r, x16, tmp16)
    }
    words.set(X, off)
  }
  for (let i = 0; i < words.length; i++) {
    const o = i * 4
    const v = words[i]
    B[o] = v & 0xff
    B[o + 1] = (v >>> 8) & 0xff
    B[o + 2] = (v >>> 16) & 0xff
    B[o + 3] = (v >>> 24) & 0xff
  }
  return pbkdf2Js('sha256', password, B, 1, dkLen)
}
