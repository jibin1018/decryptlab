/* DecryptLab — 공통 코어
 * 바이트/문자열 변환, 입출력 형식, 외부 라이브러리 지연 로딩, 카테고리 레지스트리.
 *
 * 도구(tool) 정의 형식
 *   { id, name, short, desc,
 *     modes?: [{ id, label, inLabel?, outLabel?, placeholder? }],  // 기본: 인코딩/디코딩
 *     options?: [{ id, label, type, default, choices?, mode?, wide? }],
 *     fileInput?: true,   // 파일 열기 버튼 표시 (입력이 Uint8Array로 전달됨)
 *     slow?: true,        // 입력 디바운스 (무거운 연산)
 *     [modeId]: (input, opts) => string | Uint8Array | { text, html } | Promise<…> }
 */
(function (root) {
  'use strict';
  const DL = (root.DecryptLab = root.DecryptLab || {});
  DL.CATEGORIES = DL.CATEGORIES || [];
  DL.fn = DL.fn || {};

  /* ---------- 텍스트 / 바이트 ---------- */
  const te = new TextEncoder();
  const utf8 = (s) => te.encode(s);
  const utf8Decode = (b, fatal = false) => new TextDecoder('utf-8', { fatal }).decode(b);
  const latin1 = (b) => {
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return s;
  };
  const fromLatin1 = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 255);
  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  const toHex = (bytes, upper = false, sep = '') => {
    const parts = Array.from(bytes, (b) => {
      const h = b.toString(16).padStart(2, '0');
      return upper ? h.toUpperCase() : h;
    });
    if (sep === '\\x') return parts.map((p) => '\\x' + p).join('');
    if (sep === '0x') return parts.map((p) => '0x' + p).join(' ');
    return parts.join(sep);
  };
  const fromHex = (s) => {
    const clean = s.replace(/\\x|0x/gi, '').replace(/[\s:,;\-]/g, '');
    if (/[^0-9a-fA-F]/.test(clean)) throw new Error('16진수가 아닌 문자가 포함되어 있습니다.');
    if (clean.length % 2) throw new Error('16진수 길이가 홀수입니다.');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  };

  function b64encode(bytes, { urlsafe = false, nopad = false } = {}) {
    let s = root.btoa(latin1(bytes));
    if (urlsafe) s = s.replace(/\+/g, '-').replace(/\//g, '_');
    if (nopad) s = s.replace(/=+$/, '');
    return s;
  }
  function b64decode(s) {
    let clean = s.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (/[^A-Za-z0-9+/=]/.test(clean)) throw new Error('Base64 문자 집합에 없는 문자가 있습니다.');
    clean = clean.replace(/=+$/, '');
    if (/=/.test(clean)) throw new Error('Base64 패딩(=) 위치가 올바르지 않습니다.');
    if (clean.length % 4 === 1) throw new Error('Base64 길이가 올바르지 않습니다.');
    clean += '='.repeat((4 - (clean.length % 4)) % 4);
    return fromLatin1(root.atob(clean));
  }

  /** 파일(바이트)로 들어온 입력을 텍스트로 바꾼다. */
  const asText = (input) => (input instanceof Uint8Array ? utf8Decode(input) : input);

  /* ---------- 입출력 형식 ---------- */
  const FMT_LABEL = { text: '텍스트 (UTF-8)', hex: '16진수', base64: 'Base64' };

  /** 입력(문자열 또는 파일 바이트)을 지정한 형식으로 해석해 바이트로 만든다. */
  function readBytes(input, fmt = 'text') {
    if (input instanceof Uint8Array) return input;
    if (fmt === 'hex') return fromHex(input);
    if (fmt === 'base64') return b64decode(input.trim());
    return utf8(input);
  }
  /** 바이트를 지정한 형식의 문자열로 만든다. text인데 UTF-8이 아니면 오류. */
  function formatBytes(bytes, fmt = 'hex') {
    if (fmt === 'base64') return b64encode(bytes);
    if (fmt === 'hexs') return toHex(bytes, false, ' ');
    if (fmt === 'text') {
      try { return utf8Decode(bytes, true); }
      catch { throw new Error('결과가 UTF-8 텍스트가 아닙니다. 출력 형식을 16진수나 Base64로 바꿔 보세요.'); }
    }
    return toHex(bytes);
  }
  const fmtOption = (id, label, def, kinds = ['text', 'hex', 'base64'], mode) => ({
    id, label, type: 'select', default: def, mode,
    choices: kinds.map((k) => [k, FMT_LABEL[k] || k]),
  });

  /* ---------- 분석 지표 ---------- */
  function printableScore(text) {
    if (!text) return 0;
    let ok = 0, total = 0;
    for (const ch of text) {
      total++;
      const c = ch.codePointAt(0);
      if (c === 0xfffd) continue;
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 127 && !(c >= 0x80 && c < 0xa0))) ok++;
    }
    return ok / total;
  }
  function entropy(bytes) {
    if (!bytes.length) return 0;
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    let h = 0;
    for (const f of freq) if (f) { const p = f / bytes.length; h -= p * Math.log2(p); }
    return h;
  }
  /** 바이트가 "읽을 수 있는 텍스트"인지 0–1 점수. UTF-8이 아니면 0. */
  function textScore(bytes) {
    let s;
    try { s = utf8Decode(bytes, true); } catch { return 0; }
    return printableScore(s);
  }

  /* ---------- PEM ---------- */
  function toPem(der, label) {
    const b = b64encode(der).match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${b.join('\n')}\n-----END ${label}-----`;
  }
  function fromPem(text) {
    const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
    if (!m) throw new Error('PEM 블록(-----BEGIN … -----)을 찾을 수 없습니다.');
    return { label: m[1], der: b64decode(m[2].replace(/^[A-Za-z-]+:.*$/gm, '')) };
  }

  /* ---------- ASN.1 DER ---------- */
  /** DER을 트리로 파싱한다. 각 노드: { cls, tag, constructed, offset, hdrLen, len, value, children? } */
  function asn1Parse(bytes, offset = 0, end = bytes.length, depth = 0) {
    if (depth > 40) throw new Error('ASN.1 중첩이 너무 깊습니다.');
    const nodes = [];
    let p = offset;
    while (p < end) {
      const start = p;
      const b0 = bytes[p++];
      const cls = b0 >> 6, constructed = !!(b0 & 0x20);
      let tag = b0 & 0x1f;
      if (tag === 0x1f) { tag = 0; let b; do { b = bytes[p++]; tag = (tag << 7) | (b & 0x7f); } while (b & 0x80); }
      if (p >= end + 1) throw new Error('ASN.1 길이 정보가 잘렸습니다.');
      let len = bytes[p++];
      if (len & 0x80) {
        const n = len & 0x7f;
        if (n === 0 || n > 4) throw new Error(`지원하지 않는 ASN.1 길이 형식입니다 (offset ${start}).`);
        len = 0;
        for (let i = 0; i < n; i++) len = len * 256 + bytes[p++];
      }
      if (p + len > end) throw new Error(`ASN.1 데이터가 잘렸습니다 (offset ${start}, 길이 ${len}).`);
      const node = { cls, tag, constructed, offset: start, hdrLen: p - start, len, value: bytes.subarray(p, p + len) };
      if (constructed) node.children = asn1Parse(bytes, p, p + len, depth + 1);
      else if (cls === 0 && tag === 3 && len > 1 && bytes[p] === 0) {
        // BIT STRING 안에 DER이 들어 있으면 펼친다 (공개키 등)
        try { const inner = asn1Parse(bytes, p + 1, p + len, depth + 1); if (inner.length && inner[0].constructed) node.children = inner; } catch { /* 일반 비트열 */ }
      } else if (cls === 0 && tag === 4 && len > 1 && (bytes[p] === 0x30 || bytes[p] === 0x04)) {
        try { const inner = asn1Parse(bytes, p, p + len, depth + 1); if (inner.length === 1 && inner[0].hdrLen + inner[0].len === len) node.children = inner; } catch { /* 일반 옥텟열 */ }
      }
      nodes.push(node);
      p += len;
    }
    return nodes;
  }
  function derLen(n) {
    if (n < 0x80) return Uint8Array.of(n);
    const b = [];
    while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); }
    return Uint8Array.of(0x80 | b.length, ...b);
  }
  const der = (tag, ...parts) => { const body = concat(...parts); return concat(Uint8Array.of(tag), derLen(body.length), body); };
  const derOid = (oid) => {
    const p = oid.split('.').map(Number);
    const out = [40 * p[0] + p[1]];
    for (const v of p.slice(2)) {
      const enc = [v & 0x7f];
      let x = Math.floor(v / 128);
      while (x > 0) { enc.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); }
      out.push(...enc);
    }
    return der(0x06, Uint8Array.from(out));
  };
  function oidToString(v) {
    const parts = [Math.floor(v[0] / 40), v[0] % 40];
    let x = 0;
    for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { parts.push(x); x = 0; } }
    return parts.join('.');
  }
  const bigFromBytes = (b) => (b.length ? BigInt('0x' + toHex(b)) : 0n);
  const bigToBytes = (n, len = 0) => { let h = n.toString(16); if (h.length % 2) h = '0' + h; const b = fromHex(h); if (len > b.length) { const o = new Uint8Array(len); o.set(b, len - b.length); return o; } return b; };

  /* ---------- MD5 / CRC32 (Web Crypto에 없는 해시) ---------- */
  const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  function md5(bytes) {
    const len = bytes.length;
    const nBlocks = ((len + 8) >>> 6) + 1;
    const w = new Uint32Array(nBlocks * 16);
    for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
    w[len >> 2] |= 0x80 << ((len % 4) * 8);
    w[nBlocks * 16 - 2] = (len * 8) >>> 0;
    w[nBlocks * 16 - 1] = Math.floor((len * 8) / 2 ** 32);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let blk = 0; blk < nBlocks; blk++) {
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        const s = MD5_S[(i >> 4) * 4 + (i % 4)];
        F = (F + A + MD5_K[i] + w[blk * 16 + g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    [a0, b0, c0, d0].forEach((v, i) => { for (let j = 0; j < 4; j++) out[i * 4 + j] = (v >>> (j * 8)) & 255; });
    return out;
  }
  let CRC_TABLE;
  function crc32(bytes) {
    if (!CRC_TABLE) {
      CRC_TABLE = new Uint32Array(256);
      for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        CRC_TABLE[n] = c >>> 0;
      }
    }
    let crc = 0xffffffff;
    for (const b of bytes) crc = CRC_TABLE[(crc ^ b) & 255] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  /* ---------- 동기 SHA-2 (HMAC 무차별 대입 등 반복 연산용) ---------- */
  const K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  function sha256(bytes) {
    const rr = (x, n) => (x >>> n) | (x << (32 - n));
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const len = bytes.length;
    const padLen = (Math.floor((len + 8) / 64) + 1) * 64;
    const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
    const dv = new DataView(m.buffer);
    const bits = len * 8;
    dv.setUint32(padLen - 4, bits >>> 0); dv.setUint32(padLen - 8, Math.floor(bits / 2 ** 32));
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
        const t1 = (hh + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i]) >>> 0;
        const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
    }
    const out = new Uint8Array(32), o = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => o.setUint32(i * 4, v));
    return out;
  }
  const K512 = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817];
  const IV512 = [0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179];
  const IV384 = [0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4];
  function sha512run(bytes, IV, outBytes) {
    const H = Uint32Array.from(IV);
    const len = bytes.length;
    const padLen = (Math.floor((len + 16) / 128) + 1) * 128;
    const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
    const dv = new DataView(m.buffer);
    const bits = len * 8;
    dv.setUint32(padLen - 4, bits >>> 0); dv.setUint32(padLen - 8, Math.floor(bits / 2 ** 32));
    const wh = new Uint32Array(80), wl = new Uint32Array(80);
    for (let off = 0; off < padLen; off += 128) {
      for (let i = 0; i < 16; i++) { wh[i] = dv.getUint32(off + i * 8); wl[i] = dv.getUint32(off + i * 8 + 4); }
      for (let i = 16; i < 80; i++) {
        const xh = wh[i - 15], xl = wl[i - 15];
        const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
        const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
        const yh = wh[i - 2], yl = wl[i - 2];
        const s1h = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);
        const s1l = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));
        let lo = (wl[i - 16] >>> 0) + (s0l >>> 0); let hi = (wh[i - 16] + s0h + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        lo += wl[i - 7] >>> 0; hi = (hi + wh[i - 7] + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        lo += s1l >>> 0; hi = (hi + s1h + (lo >= 2 ** 32 ? 1 : 0)) >>> 0;
        wh[i] = hi; wl[i] = lo >>> 0;
      }
      let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
      let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
      for (let i = 0; i < 80; i++) {
        const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
        const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
        const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
        let lo = (hl >>> 0) + (S1l >>> 0); let hi = (hh + S1h + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        lo += chl >>> 0; hi = (hi + chh + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        lo += K512[2 * i + 1] >>> 0; hi = (hi + K512[2 * i] + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        lo += wl[i] >>> 0; hi = (hi + wh[i] + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; lo >>>= 0;
        const t1h = hi, t1l = lo;
        const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
        const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
        const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch), majl = (al & bl) ^ (al & cl) ^ (bl & cl);
        let lo2 = (S0l >>> 0) + (majl >>> 0); const t2h = (S0h + majh + (lo2 >= 2 ** 32 ? 1 : 0)) >>> 0, t2l = lo2 >>> 0;
        hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
        let loe = (dl >>> 0) + (t1l >>> 0); eh = (dh + t1h + (loe >= 2 ** 32 ? 1 : 0)) >>> 0; el = loe >>> 0;
        dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
        let loa = (t1l >>> 0) + (t2l >>> 0); ah = (t1h + t2h + (loa >= 2 ** 32 ? 1 : 0)) >>> 0; al = loa >>> 0;
      }
      const addH = (idx, vh, vl) => { const lo = (H[idx + 1] >>> 0) + (vl >>> 0); H[idx] = (H[idx] + vh + (lo >= 2 ** 32 ? 1 : 0)) >>> 0; H[idx + 1] = lo >>> 0; };
      addH(0, ah, al); addH(2, bh, bl); addH(4, ch, cl); addH(6, dh, dl); addH(8, eh, el); addH(10, fh, fl); addH(12, gh, gl); addH(14, hh, hl);
    }
    const out = new Uint8Array(outBytes), o = new DataView(out.buffer);
    for (let i = 0; i * 4 < outBytes; i++) o.setUint32(i * 4, H[i]);
    return out;
  }
  const sha384 = (b) => sha512run(b, IV384, 48);
  const sha512 = (b) => sha512run(b, IV512, 64);
  function hmacSync(variant, key, msg) {
    const blockSize = variant === 256 ? 64 : 128;
    const hash = variant === 256 ? sha256 : variant === 384 ? sha384 : sha512;
    let k = key.length > blockSize ? hash(key) : key;
    const ipad = new Uint8Array(blockSize), opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) { const kb = k[i] || 0; ipad[i] = kb ^ 0x36; opad[i] = kb ^ 0x5c; }
    return hash(concat(opad, hash(concat(ipad, msg))));
  }

  const subtle = () => {
    if (!(root.crypto && root.crypto.subtle)) throw new Error('Web Crypto를 사용할 수 없습니다. https 또는 localhost에서 열어 주세요.');
    return root.crypto.subtle;
  };
  const randomBytes = (n) => root.crypto.getRandomValues(new Uint8Array(n));

  /* ---------- 레지스트리 ---------- */
  DL.kits = DL.kits || {}; // 카테고리별 공유 헬퍼 모음 (파일 분리용)
  DL.addCategory = (cat) => { if (!cat.tools) cat.tools = []; DL.CATEGORIES.push(cat); return cat; };
  // 카테고리는 먼저 등록되고, 각 도구 파일이 자신을 이 카테고리에 추가한다. (로드 순서 = 목차 순서)
  DL.addTool = (catId, tool) => {
    const c = DL.CATEGORIES.find((x) => x.id === catId);
    if (!c) throw new Error('알 수 없는 카테고리: ' + catId);
    c.tools.push(tool);
    return tool;
  };
  DL.findTool = (catId, toolId) => {
    const c = DL.CATEGORIES.find((x) => x.id === catId);
    return c && c.tools.find((t) => t.id === toolId);
  };

  Object.assign(DL, {
    utf8, utf8Decode, latin1, fromLatin1, concat, equalBytes, toHex, fromHex, b64encode, b64decode,
    asText, readBytes, formatBytes, fmtOption, printableScore, entropy, textScore, toPem, fromPem,
    asn1Parse, der, derOid, oidToString, bigFromBytes, bigToBytes,
    md5, crc32, sha256, sha384, sha512, hmacSync, subtle, randomBytes,
  });
})(typeof window !== 'undefined' ? window : globalThis);
