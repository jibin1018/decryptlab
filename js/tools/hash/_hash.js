/* 해시·MAC·KDF — 카테고리 셸 + 공유 해시/KDF 코어 (DL.kits.hash)
 * MD5·SHA-2/3·Keccak·SHAKE·BLAKE2/3·RIPEMD·SM3·Whirlpool·CRC·HMAC·PBKDF2·scrypt·HKDF·bcrypt·Argon2.
 * hash/shake/hmac/kdf/pwhash 도구는 같은 폴더의 개별 파일에서 등록한다.
 */
(function (DL) {
  'use strict';
  const { utf8, toHex, readBytes, formatBytes, fmtOption, concat, subtle, md5, crc32, b64encode, b64decode, randomBytes, equalBytes } = DL;

  const sha = async (algo, bytes) => new Uint8Array(await subtle().digest(algo, bytes));

  /* =================== Keccak / SHA-3 (FIPS 202) — 64비트 레인을 32비트 두 개로 =================== */
  const RC = (() => {
    const rc = (t) => {
      if (t % 255 === 0) return 1;
      let r = 1;
      for (let i = 1; i <= t % 255; i++) { r <<= 1; if (r & 0x100) r ^= 0x171; }
      return r & 1;
    };
    const out = new Uint32Array(48);
    for (let i = 0; i < 24; i++) {
      let lo = 0, hi = 0;
      for (let j = 0; j < 7; j++) {
        if (!rc(j + 7 * i)) continue;
        const bit = (1 << j) - 1;
        if (bit < 32) lo |= 1 << bit; else hi |= 1 << (bit - 32);
      }
      out[2 * i] = lo >>> 0; out[2 * i + 1] = hi >>> 0;
    }
    return out;
  })();
  const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]; // [x + 5y]
  function keccakF(s) {
    const C = new Uint32Array(10), B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const x1 = (x + 1) % 5, x4 = (x + 4) % 5;
        const dl = C[2 * x4] ^ ((C[2 * x1] << 1) | (C[2 * x1 + 1] >>> 31));
        const dh = C[2 * x4 + 1] ^ ((C[2 * x1 + 1] << 1) | (C[2 * x1] >>> 31));
        for (let y = 0; y < 5; y++) { s[2 * (x + 5 * y)] ^= dl; s[2 * (x + 5 * y) + 1] ^= dh; }
      }
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        const i = x + 5 * y, j = y + 5 * ((2 * x + 3 * y) % 5);
        let lo = s[2 * i], hi = s[2 * i + 1], n = ROT[i];
        if (n >= 32) { [lo, hi] = [hi, lo]; n -= 32; }
        if (n) { const l = (lo << n) | (hi >>> (32 - n)), h = (hi << n) | (lo >>> (32 - n)); lo = l; hi = h; }
        B[2 * j] = lo; B[2 * j + 1] = hi;
      }
      for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
        const i = 2 * (x + 5 * y), a = 2 * (((x + 1) % 5) + 5 * y), b = 2 * (((x + 2) % 5) + 5 * y);
        s[i] = B[i] ^ (~B[a] & B[b]);
        s[i + 1] = B[i + 1] ^ (~B[a + 1] & B[b + 1]);
      }
      s[0] ^= RC[2 * round]; s[1] ^= RC[2 * round + 1];
    }
  }
  function keccak(bytes, rate, dsByte, outLen) {
    const s = new Uint32Array(50);
    const xorByte = (pos, v) => { const lane = pos >> 3, k = pos & 7; s[2 * lane + (k >> 2)] ^= v << ((k & 3) * 8); };
    const getByte = (pos) => { const lane = pos >> 3, k = pos & 7; return (s[2 * lane + (k >> 2)] >>> ((k & 3) * 8)) & 255; };
    let p = 0;
    for (; p + rate <= bytes.length; p += rate) { for (let i = 0; i < rate; i++) xorByte(i, bytes[p + i]); keccakF(s); }
    const rest = bytes.length - p;
    for (let i = 0; i < rest; i++) xorByte(i, bytes[p + i]);
    xorByte(rest, dsByte); xorByte(rate - 1, 0x80);
    keccakF(s);
    const out = new Uint8Array(outLen);
    for (let o = 0; o < outLen; o += rate) {
      if (o) keccakF(s);
      for (let i = 0; i < rate && o + i < outLen; i++) out[o + i] = getByte(i);
    }
    return out;
  }
  const sha3 = (b, bits) => keccak(b, 200 - bits / 4, 0x06, bits / 8);
  const keccakHash = (b, bits) => keccak(b, 200 - bits / 4, 0x01, bits / 8);
  const shake = (b, bits, outLen) => keccak(b, 200 - bits / 4, 0x1f, outLen);

  /* =================== BLAKE2 (RFC 7693) =================== */
  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  ];
  const IV32 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  function blake2s(bytes, outLen = 32, key = new Uint8Array(0)) {
    const h = Uint32Array.from(IV32);
    h[0] ^= 0x01010000 ^ (key.length << 8) ^ outLen;
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    const compress = (block, t, last) => {
      const m = new Uint32Array(16);
      for (let i = 0; i < 16; i++) m[i] = block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
      const v = Uint32Array.from([...h, ...IV32]);
      v[12] ^= t >>> 0; v[13] ^= Math.floor(t / 2 ** 32);
      if (last) v[14] = ~v[14];
      const G = (a, b, c, d, x, y) => {
        v[a] = v[a] + v[b] + x; v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d]; v[b] = rotr(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y; v[d] = rotr(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d]; v[b] = rotr(v[b] ^ v[c], 7);
      };
      for (let r = 0; r < 10; r++) {
        const s = SIGMA[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]); G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]); G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    };
    return blake2run(bytes, key, 64, compress, () => {
      const out = new Uint8Array(32);
      for (let i = 0; i < 8; i++) for (let j = 0; j < 4; j++) out[4 * i + j] = (h[i] >>> (8 * j)) & 255;
      return out.slice(0, outLen);
    });
  }
  function blake2run(bytes, key, bs, compress, finish) {
    let data = bytes;
    if (key.length) { const k = new Uint8Array(bs); k.set(key); data = concat(k, bytes); }
    let t = 0;
    const n = data.length;
    if (n === 0) { compress(new Uint8Array(bs), 0, true); return finish(); }
    for (let p = 0; p < n; p += bs) {
      const last = p + bs >= n;
      const block = new Uint8Array(bs); block.set(data.subarray(p, p + bs));
      t += Math.min(bs, n - p);
      compress(block, t, last);
    }
    return finish();
  }
  // BLAKE2b: 64비트 연산을 (lo, hi) 32비트 쌍으로
  const IV64 = [0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19];
  function blake2b(bytes, outLen = 64, key = new Uint8Array(0)) {
    const h = Uint32Array.from(IV64);
    h[0] ^= 0x01010000 ^ (key.length << 8) ^ outLen;
    const v = new Uint32Array(32), m = new Uint32Array(32);
    const add = (a, b) => { // v[a] += v[b]
      const lo = v[a] + v[b]; let hi = v[a + 1] + v[b + 1];
      if (lo >= 2 ** 32) hi++;
      v[a] = lo; v[a + 1] = hi;
    };
    const addM = (a, i) => {
      const lo = v[a] + m[i]; let hi = v[a + 1] + m[i + 1];
      if (lo >= 2 ** 32) hi++;
      v[a] = lo; v[a + 1] = hi;
    };
    const xorRot = (a, b, n) => { // v[a] = rotr64(v[a] ^ v[b], n)
      let lo = v[a] ^ v[b], hi = v[a + 1] ^ v[b + 1];
      if (n === 32) { [lo, hi] = [hi, lo]; }
      else if (n < 32) { const l = (lo >>> n) | (hi << (32 - n)), hh = (hi >>> n) | (lo << (32 - n)); lo = l; hi = hh; }
      else { n -= 32; const l = (hi >>> n) | (lo << (32 - n)), hh = (lo >>> n) | (hi << (32 - n)); lo = l; hi = hh; }
      v[a] = lo; v[a + 1] = hi;
    };
    const G = (a, b, c, d, x, y) => {
      a *= 2; b *= 2; c *= 2; d *= 2;
      add(a, b); addM(a, 2 * x); xorRot(d, a, 32);
      add(c, d); xorRot(b, c, 24);
      add(a, b); addM(a, 2 * y); xorRot(d, a, 16);
      add(c, d); xorRot(b, c, 63);
    };
    const compress = (block, t, last) => {
      for (let i = 0; i < 32; i++) m[i] = block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
      v.set(h); v.set(IV64, 16);
      v[24] ^= t >>> 0; v[25] ^= Math.floor(t / 2 ** 32);
      if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
      for (let r = 0; r < 12; r++) {
        const s = SIGMA[r % 10];
        G(0, 4, 8, 12, s[0], s[1]); G(1, 5, 9, 13, s[2], s[3]); G(2, 6, 10, 14, s[4], s[5]); G(3, 7, 11, 15, s[6], s[7]);
        G(0, 5, 10, 15, s[8], s[9]); G(1, 6, 11, 12, s[10], s[11]); G(2, 7, 8, 13, s[12], s[13]); G(3, 4, 9, 14, s[14], s[15]);
      }
      for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
    };
    return blake2run(bytes, key, 128, compress, () => {
      const out = new Uint8Array(64);
      for (let i = 0; i < 16; i++) for (let j = 0; j < 4; j++) out[4 * i + j] = (h[i] >>> (8 * j)) & 255;
      return out.slice(0, outLen);
    });
  }

  /* =================== 체크섬 =================== */
  function adler32(b) {
    let a = 1, c = 0;
    for (let i = 0; i < b.length; i++) { a = (a + b[i]) % 65521; c = (c + a) % 65521; }
    return ((c << 16) | a) >>> 0;
  }
  function crcGeneric(b, { width, poly, init, refin, refout, xorout }) {
    // BigInt 없이 처리하기 위해 64비트는 별도 함수 사용
    const top = 1 << (width - 1), mask = width === 32 ? 0xffffffff : (1 << width) - 1;
    let crc = init;
    const reflect = (v, n) => { let r = 0; for (let i = 0; i < n; i++) if (v & (1 << i)) r |= 1 << (n - 1 - i); return r >>> 0; };
    for (const byte of b) {
      crc ^= (refin ? reflect(byte, 8) : byte) << (width - 8);
      for (let k = 0; k < 8; k++) crc = (crc & top ? (crc << 1) ^ poly : crc << 1) & mask;
    }
    if (refout) crc = reflect(crc, width);
    return ((crc ^ xorout) & mask) >>> 0;
  }
  let CRC32C_T;
  function crc32c(b) {
    if (!CRC32C_T) {
      CRC32C_T = new Uint32Array(256);
      for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1; CRC32C_T[n] = c >>> 0; }
    }
    let crc = 0xffffffff;
    for (const x of b) crc = CRC32C_T[(crc ^ x) & 255] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }
  function crc64xz(b) {
    const P = 0xc96c5795d7870f42n;
    let crc = 0xffffffffffffffffn;
    for (const x of b) {
      crc ^= BigInt(x);
      for (let k = 0; k < 8; k++) crc = crc & 1n ? (crc >> 1n) ^ P : crc >> 1n;
    }
    return crc ^ 0xffffffffffffffffn;
  }
  function fnv1a32(b) { let h = 0x811c9dc5; for (const x of b) { h ^= x; h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }
  function fnv1a64(b) { let h = 0xcbf29ce484222325n; for (const x of b) { h ^= BigInt(x); h = (h * 0x100000001b3n) & 0xffffffffffffffffn; } return h; }
  const hx = (n, w) => n.toString(16).padStart(w, '0');
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

  /* =================== MD 방식 패딩 (64 B 블록) =================== */
  function mdPad(bytes, bigEndian) {
    const len = bytes.length;
    const total = Math.ceil((len + 9) / 64) * 64;
    const out = new Uint8Array(total);
    out.set(bytes); out[len] = 0x80;
    const dv = new DataView(out.buffer);
    const bits = len * 8;
    if (bigEndian) { dv.setUint32(total - 8, Math.floor(bits / 2 ** 32)); dv.setUint32(total - 4, bits >>> 0); }
    else { dv.setUint32(total - 8, bits >>> 0, true); dv.setUint32(total - 4, Math.floor(bits / 2 ** 32), true); }
    return dv;
  }

  /* =================== RIPEMD-160 =================== */
  const RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  const RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  const SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  const SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
  const KL = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
  const rf = (j, x, y, z) => (j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z));
  function ripemd160(bytes) {
    const dv = mdPad(bytes, false);
    let h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    const X = new Uint32Array(16);
    for (let off = 0; off < dv.byteLength; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + 4 * i, true);
      let [al, bl, cl, dl, el] = h, [ar, br, cr, dr, er] = h;
      for (let j = 0; j < 80; j++) {
        let t = rotl((al + rf(j, bl, cl, dl) + X[RL[j]] + KL[j >> 4]) >>> 0, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t >>> 0;
        t = rotl((ar + rf(79 - j, br, cr, dr) + X[RR[j]] + KR[j >> 4]) >>> 0, SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t >>> 0;
      }
      const t = (h[1] + cl + dr) >>> 0;
      h = [t, (h[2] + dl + er) >>> 0, (h[3] + el + ar) >>> 0, (h[4] + al + br) >>> 0, (h[0] + bl + cr) >>> 0];
    }
    const out = new Uint8Array(20);
    const o = new DataView(out.buffer);
    h.forEach((v, i) => o.setUint32(4 * i, v, true));
    return out;
  }

  /* =================== SM3 (GB/T 32905) =================== */
  function sm3(bytes) {
    const dv = mdPad(bytes, true);
    const V = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    const P0 = (x) => (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0, P1 = (x) => (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0;
    const W = new Uint32Array(68), W1 = new Uint32Array(64);
    for (let off = 0; off < dv.byteLength; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + 4 * i);
      for (let j = 16; j < 68; j++) W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6];
      for (let j = 0; j < 64; j++) W1[j] = W[j] ^ W[j + 4];
      let [A, B, C, D, E, F, G, H] = V;
      for (let j = 0; j < 64; j++) {
        const T = j < 16 ? 0x79cc4519 : 0x7a879d8a;
        const SS1 = rotl((rotl(A, 12) + E + rotl(T, j % 32)) >>> 0, 7);
        const SS2 = (SS1 ^ rotl(A, 12)) >>> 0;
        const FF = j < 16 ? A ^ B ^ C : (A & B) | (A & C) | (B & C);
        const GG = j < 16 ? E ^ F ^ G : (E & F) | (~E & G);
        const TT1 = (FF + D + SS2 + W1[j]) >>> 0, TT2 = (GG + H + SS1 + W[j]) >>> 0;
        D = C; C = rotl(B, 9); B = A; A = TT1; H = G; G = rotl(F, 19); F = E; E = P0(TT2);
      }
      [A, B, C, D, E, F, G, H].forEach((v, i) => { V[i] = (V[i] ^ v) >>> 0; });
    }
    const out = new Uint8Array(32);
    const o = new DataView(out.buffer);
    V.forEach((v, i) => o.setUint32(4 * i, v));
    return out;
  }

  /* =================== xxHash32 / xxHash64 / MurmurHash3 =================== */
  function xxh32(b, seed = 0) {
    const P1 = 2654435761, P2 = 2246822519, P3 = 3266489917, P4 = 668265263, P5 = 374761393;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const round = (acc, lane) => Math.imul(rotl((acc + Math.imul(lane, P2)) >>> 0, 13), P1) >>> 0;
    let p = 0, h;
    if (b.length >= 16) {
      let v1 = (seed + P1 + P2) >>> 0, v2 = (seed + P2) >>> 0, v3 = seed >>> 0, v4 = (seed - P1) >>> 0;
      for (; p + 16 <= b.length; p += 16) {
        v1 = round(v1, dv.getUint32(p, true)); v2 = round(v2, dv.getUint32(p + 4, true));
        v3 = round(v3, dv.getUint32(p + 8, true)); v4 = round(v4, dv.getUint32(p + 12, true));
      }
      h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) >>> 0;
    } else h = (seed + P5) >>> 0;
    h = (h + b.length) >>> 0;
    for (; p + 4 <= b.length; p += 4) h = Math.imul(rotl((h + Math.imul(dv.getUint32(p, true), P3)) >>> 0, 17), P4) >>> 0;
    for (; p < b.length; p++) h = Math.imul(rotl((h + Math.imul(b[p], P5)) >>> 0, 11), P1) >>> 0;
    h ^= h >>> 15; h = Math.imul(h, P2); h ^= h >>> 13; h = Math.imul(h, P3); h ^= h >>> 16;
    return h >>> 0;
  }
  function xxh64(b, seed = 0n) {
    const M = (1n << 64n) - 1n;
    const P1 = 11400714785074694791n, P2 = 14029467366897019727n, P3 = 1609587929392839161n, P4 = 9650029242287828579n, P5 = 2870177450012600261n;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const rot = (x, n) => ((x << n) | (x >> (64n - n))) & M;
    const round = (acc, lane) => (rot((acc + lane * P2) & M, 31n) * P1) & M;
    const merge = (acc, v) => (((acc ^ round(0n, v)) * P1) + P4) & M;
    let p = 0, h;
    if (b.length >= 32) {
      let v1 = (seed + P1 + P2) & M, v2 = (seed + P2) & M, v3 = seed, v4 = (seed - P1) & M;
      for (; p + 32 <= b.length; p += 32) {
        v1 = round(v1, dv.getBigUint64(p, true)); v2 = round(v2, dv.getBigUint64(p + 8, true));
        v3 = round(v3, dv.getBigUint64(p + 16, true)); v4 = round(v4, dv.getBigUint64(p + 24, true));
      }
      h = (rot(v1, 1n) + rot(v2, 7n) + rot(v3, 12n) + rot(v4, 18n)) & M;
      h = merge(merge(merge(merge(h, v1), v2), v3), v4);
    } else h = (seed + P5) & M;
    h = (h + BigInt(b.length)) & M;
    for (; p + 8 <= b.length; p += 8) h = ((rot(h ^ round(0n, dv.getBigUint64(p, true)), 27n) * P1) + P4) & M;
    if (p + 4 <= b.length) { h = ((rot(h ^ ((BigInt(dv.getUint32(p, true)) * P1) & M), 23n) * P2) + P3) & M; p += 4; }
    for (; p < b.length; p++) h = (rot(h ^ ((BigInt(b[p]) * P5) & M), 11n) * P1) & M;
    h ^= h >> 33n; h = (h * P2) & M; h ^= h >> 29n; h = (h * P3) & M; h ^= h >> 32n;
    return h;
  }
  function murmur3(b, seed = 0) {
    const c1 = 0xcc9e2d51, c2 = 0x1b873593;
    let h = seed >>> 0;
    const n = b.length - (b.length % 4);
    const mix = (k) => Math.imul(rotl(Math.imul(k, c1) >>> 0, 15), c2) >>> 0;
    for (let i = 0; i < n; i += 4) {
      h ^= mix(b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24));
      h = (Math.imul(rotl(h >>> 0, 13), 5) + 0xe6546b64) >>> 0;
    }
    let k = 0;
    switch (b.length & 3) { case 3: k ^= b[n + 2] << 16; // falls through
      case 2: k ^= b[n + 1] << 8; // falls through
      case 1: k ^= b[n]; h ^= mix(k); }
    h ^= b.length;
    h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return h >>> 0;
  }

  /* =================== scrypt (RFC 7914) =================== */
  function salsa8(B) {
    const x = Uint32Array.from(B);
    const R = (a, b) => (a << b) | (a >>> (32 - b));
    for (let i = 0; i < 8; i += 2) {
      x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9); x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
      x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9); x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
      x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9); x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
      x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9); x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
      x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9); x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
      x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9); x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
      x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9); x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
      x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9); x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
    }
    for (let i = 0; i < 16; i++) B[i] = (B[i] + x[i]) >>> 0;
  }
  function blockMix(B, r) {
    const X = B.slice((2 * r - 1) * 16, 2 * r * 16);
    const Y = new Uint32Array(B.length);
    for (let i = 0; i < 2 * r; i++) {
      for (let k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
      salsa8(X);
      Y.set(X, ((i & 1) * r + (i >> 1)) * 16);
    }
    return Y;
  }
  async function scrypt(pass, salt, N, r, p, dkLen) {
    if (N < 2 || (N & (N - 1))) throw new Error('N은 2 이상의 2의 거듭제곱이어야 합니다 (예: 16384).');
    if (128 * r * N > 256 * 1024 * 1024) throw new Error('메모리 사용량(128·r·N)이 256 MB를 넘습니다. N이나 r을 줄이세요.');
    const pb = async (P, S, len) => {
      const k = await subtle().importKey('raw', P, 'PBKDF2', false, ['deriveBits']);
      return new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', salt: S, iterations: 1, hash: 'SHA-256' }, k, len * 8));
    };
    const B = await pb(pass, salt, p * 128 * r);
    const words = 32 * r;
    for (let i = 0; i < p; i++) {
      const dv = new DataView(B.buffer, i * 128 * r, 128 * r);
      let X = new Uint32Array(words);
      for (let k = 0; k < words; k++) X[k] = dv.getUint32(4 * k, true);
      const V = new Uint32Array(words * N);
      for (let n = 0; n < N; n++) { V.set(X, n * words); X = blockMix(X, r); }
      for (let n = 0; n < N; n++) {
        const j = X[(2 * r - 1) * 16] & (N - 1);
        for (let k = 0; k < words; k++) X[k] ^= V[j * words + k];
        X = blockMix(X, r);
      }
      for (let k = 0; k < words; k++) dv.setUint32(4 * k, X[k], true);
    }
    return pb(pass, B, dkLen);
  }

  /* =================== Whirlpool (ISO/IEC 10118-3) — BigInt 64비트 레인 =================== */
  const WP = (() => {
    const E = [0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF, 0x3, 0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0];
    const Rb = [0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9, 0xF, 0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0];
    const Einv = []; E.forEach((v, i) => { Einv[v] = i; });
    const sbox = new Uint8Array(256);
    for (let x = 0; x < 256; x++) { const h = E[x >> 4], l = Einv[x & 15], i = Rb[h ^ l]; sbox[x] = (E[h ^ i] << 4) | Einv[l ^ i]; }
    const gmul = (a, b) => { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1d; b >>= 1; } return p & 0xff; };
    const mask = (1n << 64n) - 1n, C0 = new Array(256);
    for (let x = 0; x < 256; x++) { const s = sbox[x]; const bs = [gmul(s, 1), gmul(s, 1), gmul(s, 4), gmul(s, 1), gmul(s, 8), gmul(s, 5), gmul(s, 2), gmul(s, 9)]; let v = 0n; for (const b of bs) v = (v << 8n) | BigInt(b); C0[x] = v; }
    const RC = [0n]; for (let r = 1; r <= 10; r++) { let v = 0n; for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(sbox[8 * (r - 1) + j]); RC[r] = v; }
    const Ct = (t, x) => { const n = BigInt(8 * t); return ((C0[x] >> n) | (C0[x] << (64n - n))) & mask; };
    const byteAt = (v, i) => Number((v >> BigInt(56 - 8 * i)) & 0xffn);
    return { RC, Ct, byteAt };
  })();
  function whirlpool(msg) {
    const { RC, Ct, byteAt } = WP;
    const bitLen = BigInt(msg.length) * 8n;
    const data = [...msg, 0x80]; while (data.length % 64 !== 32) data.push(0);
    const lb = new Array(32).fill(0); let bl = bitLen; for (let i = 31; i >= 0 && bl > 0n; i--) { lb[i] = Number(bl & 0xffn); bl >>= 8n; } data.push(...lb);
    const hash = new Array(8).fill(0n);
    for (let off = 0; off < data.length; off += 64) {
      const block = new Array(8); for (let i = 0; i < 8; i++) { let v = 0n; for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(data[off + 8 * i + j]); block[i] = v; }
      const K = hash.slice(), state = new Array(8);
      for (let i = 0; i < 8; i++) state[i] = block[i] ^ K[i];
      for (let r = 1; r <= 10; r++) {
        const L = new Array(8);
        for (let i = 0; i < 8; i++) { let v = 0n; for (let t = 0; t < 8; t++) v ^= Ct(t, byteAt(K[(i - t + 8) & 7], t)); L[i] = v; }
        L[0] ^= RC[r]; for (let i = 0; i < 8; i++) K[i] = L[i];
        const M = new Array(8);
        for (let i = 0; i < 8; i++) { let v = 0n; for (let t = 0; t < 8; t++) v ^= Ct(t, byteAt(state[(i - t + 8) & 7], t)); M[i] = v ^ K[i]; }
        for (let i = 0; i < 8; i++) state[i] = M[i];
      }
      for (let i = 0; i < 8; i++) hash[i] = hash[i] ^ state[i] ^ block[i];
    }
    const out = new Uint8Array(64); for (let i = 0; i < 8; i++) { let v = hash[i]; for (let j = 7; j >= 0; j--) { out[i * 8 + j] = Number(v & 0xffn); v >>= 8n; } }
    return out;
  }

  /* =================== BLAKE3 (트리 해싱 + XOF) =================== */
  const B3IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
  const B3PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
  function blake3(input, outLen = 32) {
    const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
    const g = (s, a, b, c, d, mx, my) => { s[a] = (s[a] + s[b] + mx) >>> 0; s[d] = rotr(s[d] ^ s[a], 16); s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr(s[b] ^ s[c], 12); s[a] = (s[a] + s[b] + my) >>> 0; s[d] = rotr(s[d] ^ s[a], 8); s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr(s[b] ^ s[c], 7); };
    const round = (s, m) => { g(s, 0, 4, 8, 12, m[0], m[1]); g(s, 1, 5, 9, 13, m[2], m[3]); g(s, 2, 6, 10, 14, m[4], m[5]); g(s, 3, 7, 11, 15, m[6], m[7]); g(s, 0, 5, 10, 15, m[8], m[9]); g(s, 1, 6, 11, 12, m[10], m[11]); g(s, 2, 7, 8, 13, m[12], m[13]); g(s, 3, 4, 9, 14, m[14], m[15]); };
    const CS = 1, CE = 2, PAR = 4, ROOT = 8;
    const compress = (cv, block, counter, blen, flags) => {
      const s = [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], B3IV[0], B3IV[1], B3IV[2], B3IV[3], counter >>> 0, Math.floor(counter / 4294967296) >>> 0, blen, flags];
      let m = block.slice();
      for (let r = 0; r < 7; r++) { round(s, m); if (r < 6) { const p = new Array(16); for (let i = 0; i < 16; i++) p[i] = m[B3PERM[i]]; m = p; } }
      for (let i = 0; i < 8; i++) { s[i] = (s[i] ^ s[i + 8]) >>> 0; s[i + 8] = (s[i + 8] ^ cv[i]) >>> 0; }
      return s;
    };
    const words = (b) => { const m = new Array(16).fill(0); for (let i = 0; i < b.length; i++) m[i >> 2] |= b[i] << ((i & 3) * 8); for (let i = 0; i < 16; i++) m[i] >>>= 0; return m; };
    const chunkOut = (chunk, counter) => {
      let cv = B3IV.slice(); const nb = Math.max(1, Math.ceil(chunk.length / 64));
      for (let i = 0; i < nb - 1; i++) { const blk = chunk.subarray(i * 64, i * 64 + 64); cv = compress(cv, words(blk), counter, 64, i === 0 ? CS : 0).slice(0, 8); }
      const i = nb - 1, blk = chunk.subarray(i * 64, i * 64 + 64);
      return { cv, block: words(blk), counter, blen: blk.length, flags: (i === 0 ? CS : 0) | CE };
    };
    const cvOf = (o) => compress(o.cv, o.block, o.counter, o.blen, o.flags).slice(0, 8);
    const leftLen = (n) => { const full = Math.floor((n - 1) / 1024); let p = 1; while (p * 2 <= full) p *= 2; return p * 1024; };
    const subtree = (inp, counter) => {
      if (inp.length <= 1024) return chunkOut(inp, counter);
      const ll = leftLen(inp.length), L = subtree(inp.subarray(0, ll), counter), Rr = subtree(inp.subarray(ll), counter + ll / 1024);
      return { cv: B3IV.slice(), block: cvOf(L).concat(cvOf(Rr)), counter: 0, blen: 64, flags: PAR };
    };
    const o = subtree(input, 0), out = new Uint8Array(outLen); let pos = 0, counter = 0;
    while (pos < outLen) { const w = compress(o.cv, o.block, counter, o.blen, o.flags | ROOT); for (let i = 0; i < 16 && pos < outLen; i++) for (let b = 0; b < 4 && pos < outLen; b++) out[pos++] = (w[i] >>> (b * 8)) & 0xff; counter++; }
    return out;
  }

  /* =================== bcrypt (EksBlowfish) =================== */
  // P_ORIG(18) + S_ORIG(1024) 블로피시 π 상수를 빅엔디안으로 담은 Base64 (bcryptjs와 동일).
  const BF_B64 = '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';
  const BF_BYTES = b64decode(BF_B64);
  const BF_P = [], BF_S = [];
  for (let i = 0; i < 18; i++) BF_P.push((BF_BYTES[i * 4] << 24 | BF_BYTES[i * 4 + 1] << 16 | BF_BYTES[i * 4 + 2] << 8 | BF_BYTES[i * 4 + 3]) >>> 0);
  for (let i = 0; i < 1024; i++) { const o = (18 + i) * 4; BF_S.push((BF_BYTES[o] << 24 | BF_BYTES[o + 1] << 16 | BF_BYTES[o + 2] << 8 | BF_BYTES[o + 3]) >>> 0); }
  const BF_C = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];
  const BCB64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const BC_INV = {}; for (let i = 0; i < BCB64.length; i++) BC_INV[BCB64[i]] = i;
  function bcB64enc(bytes, len) {
    let out = '', i = 0;
    while (i < len) {
      let c1 = bytes[i++] & 0xff; out += BCB64[(c1 >> 2) & 0x3f]; c1 = (c1 & 0x03) << 4;
      if (i >= len) { out += BCB64[c1 & 0x3f]; break; }
      let c2 = bytes[i++] & 0xff; c1 |= (c2 >> 4) & 0x0f; out += BCB64[c1 & 0x3f]; c1 = (c2 & 0x0f) << 2;
      if (i >= len) { out += BCB64[c1 & 0x3f]; break; }
      c2 = bytes[i++] & 0xff; c1 |= (c2 >> 6) & 0x03; out += BCB64[c1 & 0x3f] + BCB64[c2 & 0x3f];
    }
    return out;
  }
  function bcB64dec(str, len) {
    const out = []; let i = 0; const ch = () => BC_INV[str[i++]];
    while (out.length < len && i < str.length) {
      const c1 = ch(), c2 = ch(); out.push(((c1 << 2) | (c2 >> 4)) & 0xff); if (out.length >= len) break;
      const c3 = ch(); out.push((((c2 & 0x0f) << 4) | (c3 >> 2)) & 0xff); if (out.length >= len) break;
      const c4 = ch(); out.push((((c3 & 0x03) << 6) | c4) & 0xff);
    }
    return Uint8Array.from(out.slice(0, len));
  }
  function bcryptRaw(passBytes, cost, salt16) {
    const P = BF_P.slice(), S = BF_S.slice();
    const f = (x) => { let a = (S[(x >>> 24) & 0xff] + S[256 + ((x >>> 16) & 0xff)]) >>> 0; a = (a ^ S[512 + ((x >>> 8) & 0xff)]) >>> 0; return (a + S[768 + (x & 0xff)]) >>> 0; };
    const encipher = (lr) => {
      let l = lr[0] >>> 0, r = lr[1] >>> 0;
      for (let i = 0; i < 16; i++) { l = (l ^ P[i]) >>> 0; r = (r ^ f(l)) >>> 0; const t = l; l = r; r = t; }
      const t = l; l = r; r = t; lr[0] = (l ^ P[17]) >>> 0; lr[1] = (r ^ P[16]) >>> 0;
    };
    const stream = (data) => { let j = 0; return () => { let w = 0; for (let k = 0; k < 4; k++) w = ((w << 8) | data[j++ % data.length]) >>> 0; return w >>> 0; }; };
    const expand = (data, key) => {
      const ks = stream(key); for (let i = 0; i < 18; i++) P[i] = (P[i] ^ ks()) >>> 0;
      const ds = data ? stream(data) : () => 0; const lr = [0, 0];
      for (let i = 0; i < 18; i += 2) { lr[0] = (lr[0] ^ ds()) >>> 0; lr[1] = (lr[1] ^ ds()) >>> 0; encipher(lr); P[i] = lr[0]; P[i + 1] = lr[1]; }
      for (let i = 0; i < 1024; i += 2) { lr[0] = (lr[0] ^ ds()) >>> 0; lr[1] = (lr[1] ^ ds()) >>> 0; encipher(lr); S[i] = lr[0]; S[i + 1] = lr[1]; }
    };
    expand(salt16, passBytes);
    const rounds = 1 << cost;
    for (let k = 0; k < rounds; k++) { expand(null, passBytes); expand(null, salt16); }
    const cdata = BF_C.slice();
    for (let i = 0; i < 64; i++) for (let j = 0; j < 6; j += 2) { const lr = [cdata[j], cdata[j + 1]]; encipher(lr); cdata[j] = lr[0]; cdata[j + 1] = lr[1]; }
    const out = new Uint8Array(24); for (let i = 0; i < 6; i++) { out[i * 4] = (cdata[i] >>> 24) & 0xff; out[i * 4 + 1] = (cdata[i] >>> 16) & 0xff; out[i * 4 + 2] = (cdata[i] >>> 8) & 0xff; out[i * 4 + 3] = cdata[i] & 0xff; }
    return out.subarray(0, 23);
  }
  function bcryptHashStr(password, saltStr) {
    const m = /^\$2([abxy])\$(\d\d)\$(.{22})/.exec(saltStr);
    if (!m) throw new Error('bcrypt 솔트 형식은 $2a$비용$22자 여야 합니다.');
    const cost = parseInt(m[2], 10);
    if (cost < 4 || cost > 31) throw new Error('bcrypt 비용(cost)은 4–31이어야 합니다.');
    let pb = utf8(password); const nul = new Uint8Array(pb.length + 1); nul.set(pb); pb = nul; // null 종단
    if (pb.length > 72) pb = pb.subarray(0, 72);
    return `$2${m[1]}$${m[2]}$${m[3]}${bcB64enc(bcryptRaw(pb, cost, bcB64dec(m[3], 16)), 23)}`;
  }
  function bcryptGenSalt(cost) { return `$2b$${String(cost).padStart(2, '0')}$${bcB64enc(randomBytes(16), 16)}`; }
  function bcryptVerify(password, hashStr) { const h = hashStr.trim(); return bcryptHashStr(password, h.slice(0, 29)) === h; }

  /* =================== Argon2 (RFC 9106) — BLAKE2b 기반, BigInt 64비트 =================== */
  const A_MASK = (1n << 64n) - 1n;
  const le32b = (n) => Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  function argonHprime(X, tagLen) {
    if (tagLen <= 64) return blake2b(concat(le32b(tagLen), X), tagLen);
    const r = Math.ceil(tagLen / 32) - 2; let out = new Uint8Array(0);
    let v = blake2b(concat(le32b(tagLen), X), 64); out = concat(out, v.subarray(0, 32));
    for (let i = 1; i < r; i++) { v = blake2b(v, 64); out = concat(out, v.subarray(0, 32)); }
    return concat(out, blake2b(v, tagLen - 32 * r));
  }
  const aRotr = (x, n) => ((x >> n) | (x << (64n - n))) & A_MASK;
  function aGB(v, a, b, c, d) {
    const lo = (x) => x & 0xffffffffn;
    v[a] = (v[a] + v[b] + 2n * lo(v[a]) * lo(v[b])) & A_MASK; v[d] = aRotr(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d] + 2n * lo(v[c]) * lo(v[d])) & A_MASK; v[b] = aRotr(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + 2n * lo(v[a]) * lo(v[b])) & A_MASK; v[d] = aRotr(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d] + 2n * lo(v[c]) * lo(v[d])) & A_MASK; v[b] = aRotr(v[b] ^ v[c], 63n);
  }
  function aP(v) {
    aGB(v, 0, 4, 8, 12); aGB(v, 1, 5, 9, 13); aGB(v, 2, 6, 10, 14); aGB(v, 3, 7, 11, 15);
    aGB(v, 0, 5, 10, 15); aGB(v, 1, 6, 11, 12); aGB(v, 2, 7, 8, 13); aGB(v, 3, 4, 9, 14);
  }
  function aCompress(X, Y, out, xor) {
    const R = new BigUint64Array(128); for (let i = 0; i < 128; i++) R[i] = X[i] ^ Y[i];
    const Z = new BigUint64Array(R); const tmp = new Array(16);
    for (let r = 0; r < 8; r++) { for (let k = 0; k < 16; k++) tmp[k] = Z[r * 16 + k]; aP(tmp); for (let k = 0; k < 16; k++) Z[r * 16 + k] = tmp[k]; }
    for (let c = 0; c < 8; c++) { for (let r = 0; r < 8; r++) { tmp[2 * r] = Z[16 * r + 2 * c]; tmp[2 * r + 1] = Z[16 * r + 2 * c + 1]; } aP(tmp); for (let r = 0; r < 8; r++) { Z[16 * r + 2 * c] = tmp[2 * r]; Z[16 * r + 2 * c + 1] = tmp[2 * r + 1]; } }
    for (let i = 0; i < 128; i++) { const val = Z[i] ^ R[i]; out[i] = xor ? (out[i] ^ val) : val; }
  }
  const aBlockBytes = (blk) => { const b = new Uint8Array(1024); const dv = new DataView(b.buffer); for (let i = 0; i < 128; i++) dv.setBigUint64(i * 8, blk[i], true); return b; };
  const aBytesBlock = (bytes) => { const blk = new BigUint64Array(128); const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); for (let i = 0; i < 128; i++) blk[i] = dv.getBigUint64(i * 8, true); return blk; };
  function argon2Compute(type, pw, salt, p, tCost, mKiB, tagLen) {
    const TYPE = { d: 0, i: 1, id: 2 }[type];
    const H0 = blake2b(concat(le32b(p), le32b(tagLen), le32b(mKiB), le32b(tCost), le32b(0x13), le32b(TYPE),
      le32b(pw.length), pw, le32b(salt.length), salt, le32b(0), new Uint8Array(0), le32b(0), new Uint8Array(0)), 64);
    const mPrime = 4 * p * Math.floor(mKiB / (4 * p));
    const q = mPrime / p, segLen = q / 4;
    const B = []; for (let i = 0; i < p; i++) B.push(new Array(q));
    for (let i = 0; i < p; i++) {
      B[i][0] = aBytesBlock(argonHprime(concat(H0, le32b(0), le32b(i)), 1024));
      B[i][1] = aBytesBlock(argonHprime(concat(H0, le32b(1), le32b(i)), 1024));
    }
    const zero = new BigUint64Array(128);
    for (let pass = 0; pass < tCost; pass++) for (let slice = 0; slice < 4; slice++) for (let lane = 0; lane < p; lane++) {
      const dataIndep = (TYPE === 1) || (TYPE === 2 && pass === 0 && slice < 2);
      let addr = null, inp = null;
      if (dataIndep) { inp = new BigUint64Array(128); inp[0] = BigInt(pass); inp[1] = BigInt(lane); inp[2] = BigInt(slice); inp[3] = BigInt(mPrime); inp[4] = BigInt(tCost); inp[5] = BigInt(TYPE); addr = new BigUint64Array(128); }
      for (let idx = 0; idx < segLen; idx++) {
        if (dataIndep && (idx % 128) === 0) { inp[6] += 1n; aCompress(zero, inp, addr, false); const t2 = new BigUint64Array(128); aCompress(zero, addr, t2, false); addr.set(t2); }
        if (pass === 0 && slice === 0 && idx < 2) continue;
        const col = slice * segLen + idx, prevCol = (col === 0) ? q - 1 : col - 1;
        let J1, J2;
        if (dataIndep) { const pr = addr[idx % 128]; J1 = Number(pr & 0xffffffffn); J2 = Number((pr >> 32n) & 0xffffffffn); }
        else { const pr = B[lane][prevCol][0]; J1 = Number(pr & 0xffffffffn); J2 = Number((pr >> 32n) & 0xffffffffn); }
        const refLane = (pass === 0 && slice === 0) ? lane : (J2 % p);
        let refAreaSize;
        if (pass === 0) { if (slice === 0) refAreaSize = idx - 1; else if (refLane === lane) refAreaSize = slice * segLen + idx - 1; else refAreaSize = slice * segLen - (idx === 0 ? 1 : 0); }
        else { if (refLane === lane) refAreaSize = q - segLen + idx - 1; else refAreaSize = q - segLen - (idx === 0 ? 1 : 0); }
        if (refAreaSize < 1) refAreaSize = 1;
        const J1b = BigInt(J1), xb = (J1b * J1b) >> 32n, yb = (BigInt(refAreaSize) * xb) >> 32n, zb = BigInt(refAreaSize) - 1n - yb;
        const startPos = (pass !== 0) ? (slice === 3 ? 0 : (slice + 1) * segLen) : 0;
        const refCol = Number((BigInt(startPos) + zb) % BigInt(q));
        if (!B[lane][col]) B[lane][col] = new BigUint64Array(128);
        aCompress(B[lane][prevCol], B[refLane][refCol], B[lane][col], pass !== 0);
      }
    }
    const final = new BigUint64Array(128); for (let i = 0; i < p; i++) for (let k = 0; k < 128; k++) final[k] ^= B[i][q - 1][k];
    return argonHprime(aBlockBytes(final), tagLen);
  }
  const argonEncode = (type, p, t, m, salt, tag) => `$argon2${type}$v=19$m=${m},t=${t},p=${p}$${b64encode(salt, { nopad: true })}$${b64encode(tag, { nopad: true })}`;
  function argon2Verify(password, phc) {
    const m = /^\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/.exec(phc.trim());
    if (!m) throw new Error('Argon2 PHC 형식이 아닙니다. 예: $argon2id$v=19$m=...,t=...,p=...$salt$hash');
    if (m[2] !== '19') throw new Error(`지원하지 않는 Argon2 버전입니다 (v=${m[2]}). v=19만 지원합니다.`);
    const salt = b64decode(m[6]), tag = b64decode(m[7]);
    const got = argon2Compute(m[1], utf8(password), salt, +m[5], +m[4], +m[3], tag.length);
    return equalBytes(got, tag);
  }

  async function allHashes(bytes, group = 'common') {
    const rows = [];
    if (group === 'common' || group === 'all') {
      rows.push(['MD5', toHex(md5(bytes))], ['SHA-1', toHex(await sha('SHA-1', bytes))], ['SHA-256', toHex(await sha('SHA-256', bytes))],
        ['SHA-384', toHex(await sha('SHA-384', bytes))], ['SHA-512', toHex(await sha('SHA-512', bytes))], ['CRC32', hx(crc32(bytes), 8)]);
    }
    if (group === 'sha3' || group === 'all') {
      rows.push(['SHA3-224', toHex(sha3(bytes, 224))], ['SHA3-256', toHex(sha3(bytes, 256))], ['SHA3-384', toHex(sha3(bytes, 384))], ['SHA3-512', toHex(sha3(bytes, 512))],
        ['Keccak-256', toHex(keccakHash(bytes, 256))], ['Keccak-512', toHex(keccakHash(bytes, 512))]);
    }
    if (group === 'blake' || group === 'all') rows.push(['BLAKE2b-512', toHex(blake2b(bytes, 64))], ['BLAKE2b-256', toHex(blake2b(bytes, 32))], ['BLAKE2s-256', toHex(blake2s(bytes, 32))], ['BLAKE3-256', toHex(blake3(bytes, 32))]);
    if (group === 'checksum' || group === 'all') {
      rows.push(['CRC32', hx(crc32(bytes), 8)], ['CRC32C', hx(crc32c(bytes), 8)], ['CRC64/XZ', hx(crc64xz(bytes), 16)],
        ['CRC16/ARC', hx(crcGeneric(bytes, { width: 16, poly: 0x8005, init: 0, refin: true, refout: true, xorout: 0 }), 4)],
        ['CRC16/MODBUS', hx(crcGeneric(bytes, { width: 16, poly: 0x8005, init: 0xffff, refin: true, refout: true, xorout: 0 }), 4)],
        ['CRC16/CCITT', hx(crcGeneric(bytes, { width: 16, poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0 }), 4)],
        ['Adler-32', hx(adler32(bytes), 8)], ['FNV-1a 32', hx(fnv1a32(bytes), 8)], ['FNV-1a 64', hx(fnv1a64(bytes), 16)],
        ['xxHash32', hx(xxh32(bytes), 8)], ['xxHash64', hx(xxh64(bytes), 16)], ['Murmur3-32', hx(murmur3(bytes), 8)]);
    }
    if (group === 'etc' || group === 'all') rows.push(['RIPEMD-160', toHex(ripemd160(bytes))], ['SM3', toHex(sm3(bytes))], ['Whirlpool', toHex(whirlpool(bytes))]);
    return group === 'all' ? rows.filter((r, i) => rows.findIndex((x) => x[0] === r[0]) === i) : rows;
  }

  function hmacMd5(key, msg) {
    let k = key.length > 64 ? md5(key) : key;
    const kp = new Uint8Array(64); kp.set(k);
    const ipad = kp.map((b) => b ^ 0x36), opad = kp.map((b) => b ^ 0x5c);
    return md5(concat(opad, md5(concat(ipad, msg))));
  }
  async function hmac(algo, key, msg) {
    if (algo === 'MD5') return hmacMd5(key, msg);
    if (!key.length) throw new Error('HMAC 키를 입력하세요.');
    const k = await subtle().importKey('raw', key, { name: 'HMAC', hash: algo }, false, ['sign']);
    return new Uint8Array(await subtle().sign('HMAC', k, msg));
  }

  async function kdf(pass, o) {
    const salt = readBytes(o.salt, o.saltFmt);
    const len = Number(o.length) || 32;
    if (len < 1 || len > 1024) throw new Error('출력 길이는 1–1024 B여야 합니다.');
    if (o.kdf === 'scrypt') return scrypt(pass, salt, Number(o.N) || 16384, Number(o.r) || 8, Number(o.p) || 1, len);
    if (o.kdf === 'pbkdf2') {
      const iter = Number(o.iter) || 1;
      if (iter > 5000000) throw new Error('반복 횟수가 너무 큽니다 (최대 5,000,000).');
      const k = await subtle().importKey('raw', pass, 'PBKDF2', false, ['deriveBits']);
      return new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', salt, iterations: iter, hash: o.hash }, k, len * 8));
    }
    const k = await subtle().importKey('raw', pass, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle().deriveBits({ name: 'HKDF', salt, info: utf8(o.info || ''), hash: o.hash }, k, len * 8));
  }

  const compareLine = (target, value) => {
    const t = (target || '').trim().toLowerCase();
    if (!t) return '';
    return value.toLowerCase() === t ? '\n\n✓ 비교값과 일치합니다.' : '\n\n✗ 비교값과 일치하지 않습니다.';
  };

  Object.assign(DL.fn, { ripemd160, sm3, xxh32, xxh64, murmur3, scrypt, allHashes, hmac, sha3, keccakHash, shake, blake2b, blake2s, blake3, whirlpool, adler32, crc32c, crc64xz, crcGeneric, fnv1a32, fnv1a64, bcryptHashStr, bcryptGenSalt, bcryptVerify, argon2Compute, argonEncode, argon2Verify });

  const HASHES = [['SHA-256', 'SHA-256'], ['SHA-1', 'SHA-1'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']];

  DL.kits.hash = {
    utf8, readBytes, formatBytes, fmtOption, randomBytes,
    allHashes, blake3, shake, hmac, kdf, compareLine, HASHES,
    bcryptHashStr, bcryptGenSalt, bcryptVerify, argonEncode, argon2Compute, argon2Verify,
  };

  DL.addCategory({
    id: 'hash',
    name: '해시·MAC·KDF',
    desc: 'MD5·SHA 해시와 CRC32 체크섬, HMAC 메시지 인증, PBKDF2·HKDF 키 유도',
    color: 'red',
    tools: [],
    planned: [],
  });
})(globalThis.DecryptLab);
