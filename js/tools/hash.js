/* 해시·MAC·KDF */
(function (DL) {
  'use strict';
  const { utf8, toHex, readBytes, formatBytes, fmtOption, concat, subtle, md5, crc32 } = DL;

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
    if (group === 'blake' || group === 'all') rows.push(['BLAKE2b-512', toHex(blake2b(bytes, 64))], ['BLAKE2b-256', toHex(blake2b(bytes, 32))], ['BLAKE2s-256', toHex(blake2s(bytes, 32))]);
    if (group === 'checksum' || group === 'all') {
      rows.push(['CRC32', hx(crc32(bytes), 8)], ['CRC32C', hx(crc32c(bytes), 8)], ['CRC64/XZ', hx(crc64xz(bytes), 16)],
        ['CRC16/ARC', hx(crcGeneric(bytes, { width: 16, poly: 0x8005, init: 0, refin: true, refout: true, xorout: 0 }), 4)],
        ['CRC16/MODBUS', hx(crcGeneric(bytes, { width: 16, poly: 0x8005, init: 0xffff, refin: true, refout: true, xorout: 0 }), 4)],
        ['CRC16/CCITT', hx(crcGeneric(bytes, { width: 16, poly: 0x1021, init: 0xffff, refin: false, refout: false, xorout: 0 }), 4)],
        ['Adler-32', hx(adler32(bytes), 8)], ['FNV-1a 32', hx(fnv1a32(bytes), 8)], ['FNV-1a 64', hx(fnv1a64(bytes), 16)],
        ['xxHash32', hx(xxh32(bytes), 8)], ['xxHash64', hx(xxh64(bytes), 16)], ['Murmur3-32', hx(murmur3(bytes), 8)]);
    }
    if (group === 'etc' || group === 'all') rows.push(['RIPEMD-160', toHex(ripemd160(bytes))], ['SM3', toHex(sm3(bytes))]);
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

  Object.assign(DL.fn, { ripemd160, sm3, xxh32, xxh64, murmur3, scrypt, allHashes, hmac, sha3, keccakHash, shake, blake2b, blake2s, adler32, crc32c, crc64xz, crcGeneric, fnv1a32, fnv1a64 });

  const HASHES = [['SHA-256', 'SHA-256'], ['SHA-1', 'SHA-1'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']];

  DL.addCategory({
    id: 'hash',
    name: '해시·MAC·KDF',
    desc: 'MD5·SHA 해시와 CRC32 체크섬, HMAC 메시지 인증, PBKDF2·HKDF 키 유도',
    color: 'red',
    tools: [
      {
        id: 'hash', name: '해시 생성', short: 'MD5 · SHA-2/3 · BLAKE2 · RIPEMD · 체크섬',
        desc: '입력의 해시값을 한 번에 계산합니다. 해시는 단방향이라 복호화할 수 없고, 같은 입력인지 비교하는 데 씁니다. "비교값"에 해시를 넣으면 어느 알고리즘과 일치하는지 알려줍니다.',
        fileInput: true, slow: true,
        modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
        options: [
          { id: 'group', label: '알고리즘', type: 'select', default: 'common', choices: [['common', 'MD5 · SHA-1 · SHA-2'], ['sha3', 'SHA-3 · Keccak'], ['blake', 'BLAKE2'], ['etc', 'RIPEMD-160 · SM3'], ['checksum', '체크섬·비암호 해시'], ['all', '전체']] },
          fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
          { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
        ],
        run: async (s, o) => {
          const rows = await allHashes(readBytes(s, o.inFmt), o.group);
          const t = (o.compare || '').trim().toLowerCase();
          const out = rows.map(([k, v]) => `${k.padEnd(13)} ${v}${t && v === t ? '   ← 일치' : ''}`).join('\n');
          if (!t) return out;
          return out + (rows.some(([, v]) => v === t) ? '' : '\n\n✗ 비교값과 일치하는 해시가 없습니다.');
        },
      },
      {
        id: 'shake', name: 'SHAKE (가변 길이)', short: 'SHAKE128 · SHAKE256 XOF',
        desc: 'SHA-3 계열의 확장 출력 함수(XOF)로, 원하는 길이만큼 해시를 뽑을 수 있습니다. 키 유도나 ML-KEM·ML-DSA 같은 양자내성 암호 내부에서 쓰입니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '계산', inLabel: '입력', outLabel: '출력' }],
        options: [
          { id: 'bits', label: '종류', type: 'select', default: '256', choices: [['128', 'SHAKE128'], ['256', 'SHAKE256']] },
          { id: 'len', label: '출력 길이(B)', type: 'number', default: 32, min: 1, max: 4096 },
          fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
          fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
        ],
        run: (s, o) => {
          const len = Number(o.len) || 32;
          if (len < 1 || len > 4096) throw new Error('출력 길이는 1–4096 B여야 합니다.');
          return formatBytes(shake(readBytes(s, o.inFmt), Number(o.bits), len), o.outFmt);
        },
      },
      {
        id: 'hmac', name: 'HMAC', short: '키가 있는 메시지 인증 코드',
        desc: '비밀키와 해시를 결합해 메시지가 변조되지 않았고 키를 가진 쪽이 만들었음을 증명합니다. API 요청 서명, 웹훅 검증, JWT HS256 등에 쓰입니다.',
        fileInput: true,
        modes: [{ id: 'run', label: 'HMAC 계산', inLabel: '메시지', outLabel: 'HMAC' }],
        options: [
          { id: 'algo', label: '해시', type: 'select', default: 'SHA-256', choices: [...HASHES, ['MD5', 'MD5']] },
          { id: 'key', label: '키', type: 'text', default: 'secret', wide: true },
          fmtOption('keyFmt', '키 형식', 'text'),
          fmtOption('inFmt', '메시지 형식', 'text'),
          fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
          { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
        ],
        run: async (s, o) => {
          const v = formatBytes(await hmac(o.algo, readBytes(o.key, o.keyFmt), readBytes(s, o.inFmt)), o.outFmt);
          return v + compareLine(o.compare, v);
        },
      },
      {
        id: 'kdf', name: 'PBKDF2 · scrypt · HKDF', short: '비밀번호/비밀값 → 암호화 키',
        desc: 'PBKDF2는 비밀번호를 여러 번 해시해 무차별 대입을 느리게 만들고, scrypt는 여기에 많은 메모리를 요구해 GPU 공격까지 어렵게 합니다. HKDF는 키 교환으로 얻은 비밀값에서 용도별 키를 뽑아냅니다. 입력 칸에 비밀번호(또는 비밀값)를 넣으세요.',
        slow: true,
        modes: [{ id: 'run', label: '키 유도', inLabel: '비밀번호 / 비밀값', outLabel: '유도된 키' }],
        options: [
          { id: 'kdf', label: '방식', type: 'select', default: 'pbkdf2', choices: [['pbkdf2', 'PBKDF2'], ['scrypt', 'scrypt'], ['hkdf', 'HKDF']] },
          { id: 'hash', label: '해시', type: 'select', default: 'SHA-256', choices: HASHES, when: (o) => o.kdf !== 'scrypt' },
          { id: 'N', label: 'N (비용)', type: 'number', default: 16384, min: 2, when: (o) => o.kdf === 'scrypt' },
          { id: 'r', label: 'r (블록 크기)', type: 'number', default: 8, min: 1, max: 32, when: (o) => o.kdf === 'scrypt' },
          { id: 'p', label: 'p (병렬도)', type: 'number', default: 1, min: 1, max: 16, when: (o) => o.kdf === 'scrypt' },
          { id: 'salt', label: '솔트', type: 'text', default: 'salt' },
          fmtOption('saltFmt', '솔트 형식', 'text'),
          { id: 'iter', label: '반복 횟수', type: 'number', default: 100000, min: 1, when: (o) => o.kdf === 'pbkdf2' },
          { id: 'info', label: 'info', type: 'text', default: '', when: (o) => o.kdf === 'hkdf' },
          { id: 'length', label: '출력 길이(B)', type: 'number', default: 32, min: 1, max: 1024 },
          fmtOption('inFmt', '입력 형식', 'text'),
          fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
        ],
        run: async (s, o) => formatBytes(await kdf(readBytes(s, o.inFmt), o), o.outFmt),
      },
    ],
    planned: [
      ['BLAKE3 · Whirlpool', '추가 암호학적 해시'],
      ['비밀번호 해시 검증', 'bcrypt · Argon2'],
    ],
  });
})(globalThis.DecryptLab);
