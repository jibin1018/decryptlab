/* 대칭키 암호
 * 블록 암호(AES·ARIA·SEED) 코어와 운용 모드(ECB·CBC·CFB·OFB·CTR·GCM)를 분리해 구현한다.
 * 모든 연산은 브라우저 안에서 이루어지며 키는 어디에도 저장하지 않는다.
 */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex, readBytes, formatBytes, fmtOption, concat, equalBytes, subtle, b64decode } = DL;

  /* =================== AES (FIPS-197) =================== */
  const SBOX = new Uint8Array(256), INV_SBOX = new Uint8Array(256);
  const rotl8 = (x, s) => ((x << s) | (x >> (8 - s))) & 0xff;
  (function () {
    let p = 1, q = 1;
    do {
      p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      SBOX[p] = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63) & 0xff;
    } while (p !== 1);
    SBOX[0] = 0x63;
    for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
  })();
  const gmul = (a, b) => {
    let r = 0;
    while (b) { if (b & 1) r ^= a; a = (a << 1) ^ (a & 0x80 ? 0x11b : 0); b >>= 1; }
    return r & 0xff;
  };
  const MUL = {};
  for (const k of [2, 3, 9, 11, 13, 14]) MUL[k] = Uint8Array.from({ length: 256 }, (_, x) => gmul(x, k));

  const AES = {
    name: 'AES', blockSize: 16, keySizes: [16, 24, 32],
    expand(key) {
      const Nk = key.length / 4, Nr = Nk + 6;
      const w = new Uint8Array(16 * (Nr + 1));
      w.set(key);
      let rcon = 1;
      for (let i = Nk; i < 4 * (Nr + 1); i++) {
        let t = Array.from(w.subarray(4 * (i - 1), 4 * i));
        if (i % Nk === 0) {
          t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
          rcon = gmul(rcon, 2);
        } else if (Nk > 6 && i % Nk === 4) t = t.map((b) => SBOX[b]);
        for (let j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - Nk) + j] ^ t[j];
      }
      return { w, Nr };
    },
    encrypt({ w, Nr }, inp) {
      const s = Uint8Array.from(inp);
      const ark = (r) => { for (let i = 0; i < 16; i++) s[i] ^= w[16 * r + i]; };
      ark(0);
      for (let r = 1; r <= Nr; r++) {
        for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        const t = s.slice();
        for (let row = 1; row < 4; row++) for (let c = 0; c < 4; c++) s[row + 4 * c] = t[row + 4 * ((c + row) % 4)];
        if (r < Nr) {
          for (let c = 0; c < 4; c++) {
            const [a0, a1, a2, a3] = s.subarray(4 * c, 4 * c + 4);
            s[4 * c] = MUL[2][a0] ^ MUL[3][a1] ^ a2 ^ a3;
            s[4 * c + 1] = a0 ^ MUL[2][a1] ^ MUL[3][a2] ^ a3;
            s[4 * c + 2] = a0 ^ a1 ^ MUL[2][a2] ^ MUL[3][a3];
            s[4 * c + 3] = MUL[3][a0] ^ a1 ^ a2 ^ MUL[2][a3];
          }
        }
        ark(r);
      }
      return s;
    },
    decrypt({ w, Nr }, inp) {
      const s = Uint8Array.from(inp);
      const ark = (r) => { for (let i = 0; i < 16; i++) s[i] ^= w[16 * r + i]; };
      ark(Nr);
      for (let r = Nr - 1; r >= 0; r--) {
        const t = s.slice();
        for (let row = 1; row < 4; row++) for (let c = 0; c < 4; c++) s[row + 4 * ((c + row) % 4)] = t[row + 4 * c];
        for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
        ark(r);
        if (r > 0) {
          for (let c = 0; c < 4; c++) {
            const [a0, a1, a2, a3] = s.subarray(4 * c, 4 * c + 4);
            s[4 * c] = MUL[14][a0] ^ MUL[11][a1] ^ MUL[13][a2] ^ MUL[9][a3];
            s[4 * c + 1] = MUL[9][a0] ^ MUL[14][a1] ^ MUL[11][a2] ^ MUL[13][a3];
            s[4 * c + 2] = MUL[13][a0] ^ MUL[9][a1] ^ MUL[14][a2] ^ MUL[11][a3];
            s[4 * c + 3] = MUL[11][a0] ^ MUL[13][a1] ^ MUL[9][a2] ^ MUL[14][a3];
          }
        }
      }
      return s;
    },
  };

  /* =================== SEED (KISA, RFC 4269) =================== */
  const SEED_S1 = fromHex('a985d6d3541dac255d43181e51fcca632844209de0e2c817a58f037bbb13d2ee708c3fa832ddf674ec950b575c5bbd01241c739810ccf2d92ce772839bd186c96050a3eb0db69e4fb75ac678a612afd561c3b441527d8d081f9900190453f7e1fd762f27b08b0eaba26e934d697c090abfeff3c58714fe64de2e4b1a06216b6602f5928a0cb37ed07a4796e52680addfa13037ae36152238f4a7454c81e9849735cbce3c7111c78975fbdaf8945982c4ff493967c0cfd7b80f8e4223916cdba434f148c26f3d2d40be3ebcc1aaba4e553bdc687f9cd84a5677a0ed46b52b65fae3b9b19f5ef9e6b231ea6d5fe4f0cd88163a58d462290733e81b0579906a2a9a');
  const SEED_S2 = fromHex('38e82da6cfdeb3b8af6055c7446f6b5bc36233b529a0e2a7d39111061cbc364bef886ca817c416f4c245e1d63f3d8e98284ef63ea5f90ddfd82b667a272ff17242d441c07367ac8bf7ad801fca2caa34d20beee95d9418f857ae08c513cd86b9ff7dc131f58a6ab1d120d7022204687107db9d9961bee659dd5190dc9aa3abd0810f471ae3ec8dbf967b5ca2a163234dc89e9c3a0c2eba6e9f5af292f34978cc15fb70757f351003646dc674d5b4ea097619fe4012e0bd05fa01f02a5ea956438514899bb0e5487997fc1e82218c1b5f7754b21d254f0046ed5852eb7edac9fd3095653cb6e4bb7c0e5039263284699337e724a4cb530a87d94c838fce3b4ab7');
  const M = [0xfc, 0xf3, 0xcf, 0x3f];
  const word = (b3, b2, b1, b0) => ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) >>> 0;
  const SS = [0, 1, 2, 3].map(() => new Uint32Array(256));
  for (let x = 0; x < 256; x++) {
    const y1 = SEED_S1[x], y2 = SEED_S2[x];
    SS[0][x] = word(y1 & M[3], y1 & M[2], y1 & M[1], y1 & M[0]);
    SS[1][x] = word(y2 & M[0], y2 & M[3], y2 & M[2], y2 & M[1]);
    SS[2][x] = word(y1 & M[1], y1 & M[0], y1 & M[3], y1 & M[2]);
    SS[3][x] = word(y2 & M[2], y2 & M[1], y2 & M[0], y2 & M[3]);
  }
  const G = (v) => (SS[0][v & 255] ^ SS[1][(v >>> 8) & 255] ^ SS[2][(v >>> 16) & 255] ^ SS[3][v >>> 24]) >>> 0;
  const rd32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  const wr32 = (b, o, v) => { b[o] = v >>> 24; b[o + 1] = (v >>> 16) & 255; b[o + 2] = (v >>> 8) & 255; b[o + 3] = v & 255; };
  const SEED = {
    name: 'SEED', blockSize: 16, keySizes: [16],
    expand(key) {
      let k0 = rd32(key, 0), k1 = rd32(key, 4), k2 = rd32(key, 8), k3 = rd32(key, 12);
      const rk = [];
      let kc = 0x9e3779b9;
      for (let i = 0; i < 16; i++) {
        rk.push(G((k0 + k2 - kc) >>> 0), G((k1 - k3 + kc) >>> 0));
        kc = ((kc << 1) | (kc >>> 31)) >>> 0;
        if (i % 2 === 0) { const t = k0; k0 = ((k0 >>> 8) | (k1 << 24)) >>> 0; k1 = ((k1 >>> 8) | (t << 24)) >>> 0; }
        else { const t = k2; k2 = ((k2 << 8) | (k3 >>> 24)) >>> 0; k3 = ((k3 << 8) | (t >>> 24)) >>> 0; }
      }
      return rk;
    },
    crypt(rk, inp, reverse) {
      let l0 = rd32(inp, 0), l1 = rd32(inp, 4), r0 = rd32(inp, 8), r1 = rd32(inp, 12);
      for (let i = 0; i < 16; i++) {
        const j = reverse ? 15 - i : i;
        let t0 = (r0 ^ rk[2 * j]) >>> 0, t1 = (r1 ^ rk[2 * j + 1]) >>> 0;
        t1 = G((t1 ^ t0) >>> 0);
        t0 = G((t0 + t1) >>> 0);
        t1 = G((t1 + t0) >>> 0);
        t0 = (t0 + t1) >>> 0;
        const n0 = (l0 ^ t0) >>> 0, n1 = (l1 ^ t1) >>> 0;
        l0 = r0; l1 = r1; r0 = n0; r1 = n1;
      }
      const out = new Uint8Array(16);
      wr32(out, 0, r0); wr32(out, 4, r1); wr32(out, 8, l0); wr32(out, 12, l1);
      return out;
    },
    encrypt(rk, b) { return SEED.crypt(rk, b, false); },
    decrypt(rk, b) { return SEED.crypt(rk, b, true); },
  };

  /* =================== ARIA (KS X 1213, RFC 5794) =================== */
  const SB2 = fromHex('e24e54fc94c24acc620d6a463c4d8bd15efa64cbb497be2bbc772e03d31959c11d06416b55f09969ea9c18ae63dfe7bb007366fb964c85e43a0945aa0fee10eb2d7ff429accfad918d78c895f92fcecd087a88385c832a2847dbb8c793a41253ff870e3136215848018e377432cae9b1b7ab0cd7c4564226079860d9b6b91140ec208cbda0c984044923f14f501f13dcd8c09e57e3c37b653b028f3ee82592e515ddfd17a9bfd49a7ec53967fe769d43a7e1d0f568f21b347005a38ad57986a830c6514b1ea627f635d26e2416825fdae675a2ef2cb21c9f5d6f800a72449b6c900b5b337d5a52f361a1f7b0d63f7c6ded14e0a53d22b3f889de711aafbab581');
  const SB4 = new Uint8Array(256);
  for (let i = 0; i < 256; i++) SB4[SB2[i]] = i;
  const SL1 = [SBOX, SB2, INV_SBOX, SB4], SL2 = [INV_SBOX, SB4, SBOX, SB2];
  const A_ROWS = [
    [3, 4, 6, 8, 9, 13, 14], [2, 5, 7, 8, 9, 12, 15], [1, 4, 6, 10, 11, 12, 15], [0, 5, 7, 10, 11, 13, 14],
    [0, 2, 5, 8, 11, 14, 15], [1, 3, 4, 9, 10, 14, 15], [0, 2, 7, 9, 10, 12, 13], [1, 3, 6, 8, 11, 12, 13],
    [0, 1, 4, 7, 10, 13, 15], [0, 1, 5, 6, 11, 12, 14], [2, 3, 5, 6, 8, 13, 15], [2, 3, 4, 7, 9, 12, 14],
    [1, 2, 6, 7, 9, 11, 12], [0, 3, 6, 7, 8, 10, 13], [0, 3, 4, 5, 9, 11, 14], [1, 2, 4, 5, 8, 10, 15],
  ];
  const ariaA = (x) => Uint8Array.from(A_ROWS, (row) => row.reduce((acc, i) => acc ^ x[i], 0));
  const xor16 = (a, b) => Uint8Array.from(a, (v, i) => v ^ b[i]);
  const subst = (x, sl) => Uint8Array.from(x, (v, i) => sl[i % 4][v]);
  const FO = (d, k) => ariaA(subst(xor16(d, k), SL1));
  const FE = (d, k) => ariaA(subst(xor16(d, k), SL2));
  const toBig = (b) => BigInt('0x' + toHex(b));
  const fromBig = (n) => fromHex(n.toString(16).padStart(32, '0'));
  const MASK128 = (1n << 128n) - 1n;
  const rotr128 = (x, n) => fromBig(((toBig(x) >> BigInt(n)) | (toBig(x) << BigInt(128 - n))) & MASK128);
  const ARIA_C = ['517cc1b727220a94fe13abe8fa9a6ee0', '6db14acc9e21c820ff28b1d5ef5de2b0', 'db92371d2126e9700324977504e8c90e'].map(fromHex);
  const ARIA = {
    name: 'ARIA', blockSize: 16, keySizes: [16, 24, 32],
    expand(key) {
      const kl = key.slice(0, 16);
      const kr = new Uint8Array(16); kr.set(key.slice(16));
      const order = key.length === 16 ? [0, 1, 2] : key.length === 24 ? [1, 2, 0] : [2, 0, 1];
      const [ck1, ck2, ck3] = order.map((i) => ARIA_C[i]);
      const w0 = kl;
      const w1 = xor16(FO(w0, ck1), kr);
      const w2 = xor16(FE(w1, ck2), w0);
      const w3 = xor16(FO(w2, ck3), w1);
      const W = [w0, w1, w2, w3];
      const ek = [];
      for (const rot of [19, 31, 128 - 61, 128 - 31]) {
        for (let i = 0; i < 4; i++) ek.push(xor16(W[i], rotr128(W[(i + 1) % 4], rot)));
      }
      ek.push(xor16(W[0], rotr128(W[1], 128 - 19)));
      const nr = key.length === 16 ? 12 : key.length === 24 ? 14 : 16;
      const enc = ek.slice(0, nr + 1);
      const dec = [enc[nr], ...enc.slice(1, nr).reverse().map(ariaA), enc[0]];
      return { enc, dec, nr };
    },
    crypt(keys, nr, inp) {
      let x = Uint8Array.from(inp);
      for (let r = 0; r < nr - 1; r++) x = r % 2 === 0 ? FO(x, keys[r]) : FE(x, keys[r]);
      return xor16(subst(xor16(x, keys[nr - 1]), SL2), keys[nr]);
    },
    encrypt(ctx, b) { return ARIA.crypt(ctx.enc, ctx.nr, b); },
    decrypt(ctx, b) { return ARIA.crypt(ctx.dec, ctx.nr, b); },
  };

  /* =================== 패딩 =================== */
  function pad(data, bs, scheme) {
    if (scheme === 'none') {
      if (data.length % bs) throw new Error(`패딩 없음: 데이터 길이(${data.length} B)가 블록 크기(${bs} B)의 배수가 아닙니다.`);
      return data;
    }
    const n = scheme === 'zero' && data.length % bs === 0 && data.length ? 0 : bs - (data.length % bs);
    const p = new Uint8Array(n);
    if (scheme === 'pkcs7') p.fill(n);
    if (scheme === 'x923' && n) p[n - 1] = n;
    if (scheme === 'iso7816' && n) p[0] = 0x80;
    return concat(data, p);
  }
  function unpad(data, bs, scheme) {
    if (!data.length || scheme === 'none') return data;
    if (scheme === 'zero') { let e = data.length; while (e > 0 && data[e - 1] === 0) e--; return data.slice(0, e); }
    if (scheme === 'iso7816') {
      let e = data.length - 1;
      while (e >= 0 && data[e] === 0) e--;
      if (e < 0 || data[e] !== 0x80) throw new Error('ISO/IEC 7816-4 패딩이 올바르지 않습니다. 키나 IV가 틀렸을 수 있습니다.');
      return data.slice(0, e);
    }
    const n = data[data.length - 1];
    const bad = () => { throw new Error('패딩이 올바르지 않습니다 — 키·IV·모드가 틀렸을 가능성이 높습니다. (패딩을 "없음"으로 바꾸면 원시 결과를 볼 수 있습니다)'); };
    if (n < 1 || n > bs || n > data.length) bad();
    if (scheme === 'pkcs7') for (let i = data.length - n; i < data.length; i++) if (data[i] !== n) bad();
    if (scheme === 'x923') for (let i = data.length - n; i < data.length - 1; i++) if (data[i] !== 0) bad();
    return data.slice(0, data.length - n);
  }

  /* =================== 운용 모드 =================== */
  const xorInto = (a, b) => Uint8Array.from(a, (v, i) => v ^ b[i]);
  function incCounter(ctr, bytes = 16) {
    const c = Uint8Array.from(ctr);
    for (let i = c.length - 1; i >= c.length - bytes; i--) { c[i] = (c[i] + 1) & 255; if (c[i]) break; }
    return c;
  }
  function streamMode(cipher, ctx, iv, data, next) {
    const bs = cipher.blockSize;
    const out = new Uint8Array(data.length);
    let fb = iv;
    for (let i = 0; i < data.length; i += bs) {
      const ks = cipher.encrypt(ctx, fb);
      const chunk = data.subarray(i, i + bs);
      const o = Uint8Array.from(chunk, (v, j) => v ^ ks[j]);
      out.set(o, i);
      fb = next(fb, ks, chunk, o);
    }
    return out;
  }

  /* GCM: GHASH는 BigInt로 GF(2^128) 곱셈 */
  const R = 0xe1n << 120n;
  function gfmul(x, y) {
    let z = 0n, v = y;
    for (let i = 127n; i >= 0n; i--) {
      if ((x >> i) & 1n) z ^= v;
      v = v & 1n ? (v >> 1n) ^ R : v >> 1n;
    }
    return z;
  }
  function ghash(h, aad, ct) {
    let x = 0n;
    const feed = (data) => {
      for (let i = 0; i < data.length; i += 16) {
        const blk = new Uint8Array(16); blk.set(data.subarray(i, i + 16));
        x = gfmul(x ^ toBig(blk), h);
      }
    };
    feed(aad); feed(ct);
    const len = (BigInt(aad.length * 8) << 64n) | BigInt(ct.length * 8);
    return gfmul(x ^ len, h);
  }
  function gcm(cipher, ctx, iv, data, aad, tagLen, decrypt, tag) {
    const h = toBig(cipher.encrypt(ctx, new Uint8Array(16)));
    let j0;
    if (iv.length === 12) j0 = concat(iv, Uint8Array.of(0, 0, 0, 1));
    else {
      const padded = new Uint8Array(Math.ceil(iv.length / 16) * 16 + 16); padded.set(iv);
      const lenBlk = new Uint8Array(8);
      new DataView(lenBlk.buffer).setBigUint64(0, BigInt(iv.length * 8));
      padded.set(lenBlk, padded.length - 8);
      let x = 0n;
      for (let i = 0; i < padded.length; i += 16) x = gfmul(x ^ toBig(padded.subarray(i, i + 16)), h);
      j0 = fromBig(x);
    }
    const out = new Uint8Array(data.length);
    let ctr = j0;
    for (let i = 0; i < data.length; i += 16) {
      ctr = incCounter(ctr, 4);
      const ks = cipher.encrypt(ctx, ctr);
      for (let j = 0; j < 16 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
    }
    const ct = decrypt ? data : out;
    const full = xorInto(fromBig(ghash(h, aad, ct)), cipher.encrypt(ctx, j0));
    const t = full.slice(0, tagLen);
    if (decrypt && !equalBytes(t, tag)) throw new Error('인증 태그가 일치하지 않습니다 — 키·IV·AAD가 틀렸거나 데이터가 변조되었습니다.');
    return { out, tag: t };
  }

  function blockCrypt(cipher, key, iv, data, o, decrypt) {
    if (!cipher.keySizes.includes(key.length)) {
      throw new Error(`${cipher.name} 키 길이가 ${key.length} B입니다. ${cipher.keySizes.map((k) => `${k} B(${k * 8}비트)`).join(', ')} 중 하나여야 합니다.`);
    }
    const bs = cipher.blockSize;
    const ctx = cipher.expand(key);
    const mode = o.mode;
    if (mode !== 'ecb' && mode !== 'gcm' && iv.length !== bs) throw new Error(`IV는 ${bs} B여야 합니다. (현재 ${iv.length} B)`);
    if (mode === 'gcm' && !iv.length) throw new Error('GCM에는 IV(nonce)가 필요합니다. 보통 12 B를 사용합니다.');

    if (mode === 'ecb' || mode === 'cbc') {
      if (decrypt && data.length % bs) throw new Error(`암호문 길이(${data.length} B)가 블록 크기의 배수가 아닙니다. 입력 형식(Base64/Hex)을 확인하세요.`);
      const src = decrypt ? data : pad(data, bs, o.padding);
      const out = new Uint8Array(src.length);
      let prev = iv;
      for (let i = 0; i < src.length; i += bs) {
        const blk = src.subarray(i, i + bs);
        if (decrypt) {
          let p = cipher.decrypt(ctx, blk);
          if (mode === 'cbc') { p = xorInto(p, prev); prev = blk; }
          out.set(p, i);
        } else {
          const c = cipher.encrypt(ctx, mode === 'cbc' ? xorInto(blk, prev) : blk);
          if (mode === 'cbc') prev = c;
          out.set(c, i);
        }
      }
      return decrypt ? unpad(out, bs, o.padding) : out;
    }
    if (mode === 'ctr') return streamMode(cipher, ctx, iv, data, (fb) => incCounter(fb));
    if (mode === 'ofb') return streamMode(cipher, ctx, iv, data, (fb, ks) => ks);
    if (mode === 'cfb') return streamMode(cipher, ctx, iv, data, (fb, ks, inp, outp) => (decrypt ? inp : outp));
    if (mode === 'gcm') {
      const aad = utf8(o.aad || '');
      const tagLen = 16;
      if (decrypt) {
        if (data.length < tagLen) throw new Error('GCM 암호문에는 끝에 16 B 인증 태그가 붙어 있어야 합니다.');
        return gcm(cipher, ctx, iv, data.slice(0, -tagLen), aad, tagLen, true, data.slice(-tagLen)).out;
      }
      const r = gcm(cipher, ctx, iv, data, aad, tagLen, false);
      return concat(r.out, r.tag);
    }
    throw new Error(`알 수 없는 모드: ${mode}`);
  }

  /* =================== ChaCha20 / Poly1305 (RFC 8439) =================== */
  function chachaBlock(key, counter, nonce) {
    const c = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    const dv = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
    const k = dv(key), n = dv(nonce);
    const st = new Uint32Array(16);
    st.set(c);
    for (let i = 0; i < 8; i++) st[4 + i] = k.getUint32(i * 4, true);
    st[12] = counter >>> 0;
    for (let i = 0; i < 3; i++) st[13 + i] = n.getUint32(i * 4, true);
    const x = Uint32Array.from(st);
    const rotl = (v, s) => ((v << s) | (v >>> (32 - s))) >>> 0;
    const qr = (a, b, cc, d) => {
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
      x[cc] = (x[cc] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[cc], 12);
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
      x[cc] = (x[cc] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[cc], 7);
    };
    for (let i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = new Uint8Array(64);
    const o = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) o.setUint32(i * 4, (x[i] + st[i]) >>> 0, true);
    return out;
  }
  function chacha20(key, nonce, counter, data) {
    if (key.length !== 32) throw new Error(`ChaCha20 키는 32 B여야 합니다. (현재 ${key.length} B)`);
    if (nonce.length !== 12) throw new Error(`ChaCha20 nonce는 12 B여야 합니다. (현재 ${nonce.length} B)`);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 64) {
      const ks = chachaBlock(key, counter + i / 64, nonce);
      for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
    }
    return out;
  }
  const leBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
  function poly1305(key, msg) {
    const r = leBig(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s = leBig(key.subarray(16, 32));
    const p = (1n << 130n) - 5n;
    let acc = 0n;
    for (let i = 0; i < msg.length; i += 16) {
      const chunk = msg.subarray(i, i + 16);
      acc = ((acc + leBig(chunk) + (1n << BigInt(8 * chunk.length))) * r) % p;
    }
    acc = (acc + s) & MASK128;
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) { out[i] = Number(acc & 255n); acc >>= 8n; }
    return out;
  }
  function chachaPoly(key, nonce, data, aad, decrypt) {
    const otk = chachaBlock(key, 0, nonce).slice(0, 32);
    const pad16 = (n) => new Uint8Array((16 - (n % 16)) % 16);
    const lens = new Uint8Array(16);
    const tagFor = (ct) => {
      const dv = new DataView(lens.buffer);
      dv.setBigUint64(0, BigInt(aad.length), true); dv.setBigUint64(8, BigInt(ct.length), true);
      return poly1305(otk, concat(aad, pad16(aad.length), ct, pad16(ct.length), lens));
    };
    if (decrypt) {
      if (data.length < 16) throw new Error('암호문 끝에 16 B Poly1305 태그가 있어야 합니다.');
      const ct = data.slice(0, -16);
      if (!equalBytes(tagFor(ct), data.slice(-16))) throw new Error('Poly1305 인증 태그가 일치하지 않습니다 — 키·nonce·AAD가 틀렸거나 데이터가 변조되었습니다.');
      return chacha20(key, nonce, 1, ct);
    }
    const ct = chacha20(key, nonce, 1, data);
    return concat(ct, tagFor(ct));
  }

  /* =================== RC4 =================== */
  function rc4(key, data, drop = 0) {
    if (!key.length) throw new Error('RC4 키를 입력하세요.');
    const S = Uint8Array.from({ length: 256 }, (_, i) => i);
    for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
    let i = 0, j = 0;
    const next = () => { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; return S[(S[i] + S[j]) & 255]; };
    for (let d = 0; d < drop; d++) next();
    return data.map((b) => b ^ next());
  }

  /* =================== OpenSSL enc / CryptoJS 비밀번호 방식 =================== */
  function evpBytesToKey(pass, salt, len) {
    let d = new Uint8Array(0), out = new Uint8Array(0);
    while (out.length < len) { d = DL.md5(concat(d, pass, salt)); out = concat(out, d); }
    return out.slice(0, len);
  }
  async function pbkdf2(pass, salt, iter, len, hash = 'SHA-256') {
    const k = await subtle().importKey('raw', pass, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', salt, iterations: iter, hash }, k, len * 8));
  }
  const SALTED = utf8('Salted__');
  async function opensslDerive(pass, salt, keyLen, o) {
    const kiv = o.kdf === 'pbkdf2' ? await pbkdf2(pass, salt, Number(o.iter) || 10000, keyLen + 16) : await evpBytesToKey(pass, salt, keyLen + 16);
    return { key: kiv.slice(0, keyLen), iv: kiv.slice(keyLen) };
  }

  Object.assign(DL.fn, { AES, SEED, ARIA, blockCrypt, chacha20, chachaPoly, poly1305, rc4, evpBytesToKey, pad, unpad });

  /* =================== 도구 정의 =================== */
  const ENC_DEC = [
    { id: 'encrypt', label: '암호화', inLabel: '평문', outLabel: '암호문' },
    { id: 'decrypt', label: '복호화', inLabel: '암호문', outLabel: '평문' },
  ];
  const keyOpt = (def) => ({ id: 'key', label: '키', type: 'text', default: def, wide: true });
  const keyFmt = (def = 'hex') => ({ ...fmtOption('keyFmt', '키 형식', def), });
  const ivOpt = (def, label = 'IV') => ({ id: 'iv', label, type: 'text', default: def, wide: true });
  const ivFmt = { ...fmtOption('ivFmt', 'IV 형식', 'hex') };
  const ptFmt = fmtOption('ptFmt', '평문 형식', 'text', ['text', 'hex', 'base64']);
  const ctFmt = fmtOption('ctFmt', '암호문 형식', 'base64', ['base64', 'hex']);

  function blockTool({ id, cipher, name, short, desc, defaultKey, modes }) {
    const needsIv = (o) => o.mode !== 'ecb';
    return {
      id, name, short, desc, slow: true, modes: ENC_DEC,
      options: [
        { id: 'mode', label: '운용 모드', type: 'select', default: 'cbc', choices: modes },
        { id: 'padding', label: '패딩', type: 'select', default: 'pkcs7', when: (o) => o.mode === 'ecb' || o.mode === 'cbc', choices: [['pkcs7', 'PKCS#7'], ['zero', 'Zero'], ['x923', 'ANSI X9.23'], ['iso7816', 'ISO/IEC 7816-4'], ['none', '없음']] },
        keyOpt(defaultKey), keyFmt(),
        { ...ivOpt('000102030405060708090a0b0c0d0e0f'), when: needsIv },
        { ...ivFmt, when: needsIv },
        { id: 'ivPrefix', label: 'IV를 암호문 앞에 붙임', type: 'checkbox', default: false, when: needsIv },
        { id: 'aad', label: 'AAD (추가 인증 데이터)', type: 'text', default: '', when: (o) => o.mode === 'gcm' },
        ptFmt, ctFmt,
      ],
      encrypt: (s, o) => {
        const key = readBytes(o.key, o.keyFmt);
        const iv = needsIv(o) ? readBytes(o.iv, o.ivFmt) : new Uint8Array(0);
        const ct = blockCrypt(cipher, key, iv, readBytes(s, o.ptFmt), o, false);
        return formatBytes(o.ivPrefix && needsIv(o) ? concat(iv, ct) : ct, o.ctFmt);
      },
      decrypt: (s, o) => {
        const key = readBytes(o.key, o.keyFmt);
        let data = readBytes(s.trim(), o.ctFmt);
        let iv = new Uint8Array(0);
        if (needsIv(o)) {
          const ivLen = o.mode === 'gcm' ? 12 : cipher.blockSize;
          if (o.ivPrefix) { iv = data.slice(0, ivLen); data = data.slice(ivLen); } else iv = readBytes(o.iv, o.ivFmt);
        }
        return formatBytes(blockCrypt(cipher, key, iv, data, o, true), o.ptFmt);
      },
    };
  }

  const ALL_MODES = [['cbc', 'CBC'], ['ecb', 'ECB'], ['ctr', 'CTR'], ['cfb', 'CFB'], ['ofb', 'OFB'], ['gcm', 'GCM (인증 암호)']];

  DL.addCategory({
    id: 'symmetric',
    name: '대칭키 암호',
    desc: 'AES·ARIA·SEED와 ChaCha20-Poly1305 — 운용 모드·패딩·IV를 직접 지정하는 암호화와 복호화',
    color: 'teal',
    tools: [
      blockTool({
        id: 'aes', cipher: AES, name: 'AES', short: '128/192/256 · CBC·GCM·CTR 등',
        desc: '현대 표준 블록 암호입니다. 키 길이(16/24/32 B)로 AES-128/192/256이 결정됩니다. GCM은 암호문 끝에 16 B 인증 태그를 붙입니다. 결과가 깨지면 모드·IV·패딩·키 형식을 차례로 확인하세요.',
        defaultKey: '000102030405060708090a0b0c0d0e0f', modes: ALL_MODES,
      }),
      blockTool({
        id: 'aria', cipher: ARIA, name: 'ARIA', short: '국가 표준 · KS X 1213',
        desc: '국가보안기술연구소가 개발한 한국 표준 블록 암호로, 공공기관 시스템에서 널리 쓰입니다. AES와 같은 128비트 블록, 128/192/256비트 키를 사용합니다.',
        defaultKey: '000102030405060708090a0b0c0d0e0f', modes: ALL_MODES,
      }),
      blockTool({
        id: 'seed', cipher: SEED, name: 'SEED', short: 'KISA 표준 · 128비트',
        desc: '한국인터넷진흥원(KISA)이 개발한 128비트 블록 암호입니다. 과거 국내 인터넷 뱅킹과 공인인증서에서 사용되었습니다. 키는 16 B만 사용합니다.',
        defaultKey: '000102030405060708090a0b0c0d0e0f', modes: ALL_MODES,
      }),
      {
        id: 'chacha20', name: 'ChaCha20-Poly1305', short: 'RFC 8439 인증 암호',
        desc: 'TLS 1.3, WireGuard 등에서 쓰는 현대적 스트림 암호 기반 인증 암호입니다. 키 32 B, nonce 12 B를 사용하며 암호문 끝에 16 B 태그가 붙습니다. "Poly1305 없이"를 선택하면 순수 ChaCha20 스트림 암호로 동작합니다.',
        slow: true, modes: ENC_DEC,
        options: [
          { id: 'variant', label: '방식', type: 'select', default: 'aead', choices: [['aead', 'ChaCha20-Poly1305'], ['raw', 'ChaCha20 (Poly1305 없이)']] },
          keyOpt('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), keyFmt(),
          ivOpt('000000000000004a00000000', 'Nonce'), { ...ivFmt, label: 'Nonce 형식' },
          { id: 'counter', label: '초기 카운터', type: 'number', default: 1, min: 0, when: (o) => o.variant === 'raw' },
          { id: 'aad', label: 'AAD', type: 'text', default: '', when: (o) => o.variant === 'aead' },
          ptFmt, ctFmt,
        ],
        encrypt: (s, o) => {
          const key = readBytes(o.key, o.keyFmt), nonce = readBytes(o.iv, o.ivFmt), data = readBytes(s, o.ptFmt);
          const out = o.variant === 'raw' ? chacha20(key, nonce, Number(o.counter) || 0, data) : (chacha20(key, nonce, 0, new Uint8Array(0)), chachaPoly(key, nonce, data, utf8(o.aad || ''), false));
          return formatBytes(out, o.ctFmt);
        },
        decrypt: (s, o) => {
          const key = readBytes(o.key, o.keyFmt), nonce = readBytes(o.iv, o.ivFmt), data = readBytes(s.trim(), o.ctFmt);
          if (o.variant !== 'raw') chacha20(key, nonce, 0, new Uint8Array(0)); // 키/nonce 길이 검증
          const out = o.variant === 'raw' ? chacha20(key, nonce, Number(o.counter) || 0, data) : chachaPoly(key, nonce, data, utf8(o.aad || ''), true);
          return formatBytes(out, o.ptFmt);
        },
      },
      {
        id: 'openssl', name: 'OpenSSL · CryptoJS 호환', short: '비밀번호 기반 "U2FsdGVkX1…"',
        desc: '"openssl enc -aes-256-cbc"나 CryptoJS.AES.encrypt(텍스트, "비밀번호")가 만드는 형식입니다. "Salted__" + 8 B 솔트 + 암호문 구조이며, Base64로 "U2FsdGVkX1"로 시작합니다. 비밀번호에서 키와 IV를 유도합니다.',
        slow: true, modes: ENC_DEC,
        options: [
          { id: 'password', label: '비밀번호', type: 'text', default: 'password' },
          { id: 'bits', label: 'AES', type: 'select', default: '32', choices: [['32', 'AES-256-CBC'], ['24', 'AES-192-CBC'], ['16', 'AES-128-CBC']] },
          { id: 'kdf', label: '키 유도', type: 'select', default: 'md5', choices: [['md5', 'EVP_BytesToKey (MD5, CryptoJS 기본)'], ['pbkdf2', 'PBKDF2-SHA256 (openssl -pbkdf2)']] },
          { id: 'iter', label: '반복 횟수', type: 'number', default: 10000, min: 1, when: (o) => o.kdf === 'pbkdf2' },
          ptFmt,
        ],
        encrypt: async (s, o) => {
          const salt = DL.randomBytes(8);
          const { key, iv } = await opensslDerive(utf8(o.password), salt, Number(o.bits), o);
          const ct = blockCrypt(AES, key, iv, readBytes(s, o.ptFmt), { mode: 'cbc', padding: 'pkcs7' }, false);
          return DL.b64encode(concat(SALTED, salt, ct));
        },
        decrypt: async (s, o) => {
          const data = b64decode(s.trim());
          if (!equalBytes(data.slice(0, 8), SALTED)) throw new Error('"Salted__" 헤더가 없습니다. Base64가 "U2FsdGVkX1"로 시작하는지 확인하세요.');
          const { key, iv } = await opensslDerive(utf8(o.password), data.slice(8, 16), Number(o.bits), o);
          return formatBytes(blockCrypt(AES, key, iv, data.slice(16), { mode: 'cbc', padding: 'pkcs7' }, true), o.ptFmt);
        },
      },
      {
        id: 'rc4', name: 'RC4', short: '레거시 스트림 암호 · drop-N',
        desc: '과거 WEP, SSL에서 쓰였던 스트림 암호입니다. 현재는 취약하지만 악성코드의 설정·통신 암호화에 여전히 자주 등장합니다. 암호화와 복호화가 같은 연산입니다.',
        modes: ENC_DEC,
        options: [
          keyOpt('Key'), { ...keyFmt('text') },
          { id: 'drop', label: '초기 키스트림 버림 (drop)', type: 'number', default: 0, min: 0 },
          ptFmt, { ...ctFmt, default: 'hex' },
        ],
        encrypt: (s, o) => formatBytes(rc4(readBytes(o.key, o.keyFmt), readBytes(s, o.ptFmt), Number(o.drop) || 0), o.ctFmt),
        decrypt: (s, o) => formatBytes(rc4(readBytes(o.key, o.keyFmt), readBytes(s.trim(), o.ctFmt), Number(o.drop) || 0), o.ptFmt),
      },
    ],
  });
})(globalThis.DecryptLab);
