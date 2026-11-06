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

  const subtle = () => {
    if (!(root.crypto && root.crypto.subtle)) throw new Error('Web Crypto를 사용할 수 없습니다. https 또는 localhost에서 열어 주세요.');
    return root.crypto.subtle;
  };
  const randomBytes = (n) => root.crypto.getRandomValues(new Uint8Array(n));

  /* ---------- 레지스트리 ---------- */
  DL.addCategory = (cat) => { DL.CATEGORIES.push(cat); return cat; };
  DL.findTool = (catId, toolId) => {
    const c = DL.CATEGORIES.find((x) => x.id === catId);
    return c && c.tools.find((t) => t.id === toolId);
  };

  Object.assign(DL, {
    utf8, utf8Decode, latin1, fromLatin1, concat, equalBytes, toHex, fromHex, b64encode, b64decode,
    asText, readBytes, formatBytes, fmtOption, printableScore, entropy, textScore, toPem, fromPem,
    asn1Parse, der, derOid, oidToString, bigFromBytes, bigToBytes,
    md5, crc32, subtle, randomBytes,
  });
})(typeof window !== 'undefined' ? window : globalThis);
