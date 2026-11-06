/* Base 계열 인코딩 */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat, subtle, equalBytes } = DL;

  /* ---------- Base32 (RFC 4648) ---------- */
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32encode(bytes, { nopad = false } = {}) {
    let out = '', val = 0, bits = 0;
    for (const b of bytes) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
      val &= (1 << bits) - 1;
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    if (!nopad) while (out.length % 8) out += '=';
    return out;
  }
  function b32decode(s) {
    const clean = s.replace(/[\s=]/g, '').toUpperCase();
    const out = []; let val = 0, bits = 0;
    for (const c of clean) {
      const i = B32.indexOf(c);
      if (i < 0) throw new Error(`Base32 문자가 아닙니다: "${c}"`);
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; }
    }
    return new Uint8Array(out);
  }

  /* ---------- 큰 수 기반 BaseX (Base58/62/36) ---------- */
  function baseXEncode(bytes, alphabet) {
    const base = BigInt(alphabet.length);
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let s = '';
    while (n > 0n) { s = alphabet[Number(n % base)] + s; n /= base; }
    for (const b of bytes) { if (b !== 0) break; s = alphabet[0] + s; }
    return s;
  }
  function baseXDecode(str, alphabet, name, caseInsensitive = false) {
    const base = BigInt(alphabet.length);
    let clean = str.replace(/\s/g, '');
    if (caseInsensitive) clean = clean.toLowerCase();
    let n = 0n;
    for (const c of clean) {
      const i = alphabet.indexOf(c);
      if (i < 0) throw new Error(`${name} 문자가 아닙니다: "${c}"`);
      n = n * base + BigInt(i);
    }
    const out = [];
    while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
    for (const c of clean) { if (c !== alphabet[0]) break; out.unshift(0); }
    return new Uint8Array(out);
  }
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const B36 = '0123456789abcdefghijklmnopqrstuvwxyz';
  const b58encode = (b) => baseXEncode(b, B58);
  const b58decode = (s) => baseXDecode(s, B58, 'Base58');
  const b62encode = (b) => baseXEncode(b, B62);
  const b62decode = (s) => baseXDecode(s, B62, 'Base62');

  async function sha256d(bytes) {
    const h1 = new Uint8Array(await subtle().digest('SHA-256', bytes));
    return new Uint8Array(await subtle().digest('SHA-256', h1));
  }
  async function b58checkEncode(payload) {
    return b58encode(concat(payload, (await sha256d(payload)).slice(0, 4)));
  }
  async function b58checkDecode(s) {
    const all = b58decode(s);
    if (all.length < 5) throw new Error('Base58Check 데이터가 너무 짧습니다.');
    const payload = all.slice(0, -4);
    const ok = equalBytes((await sha256d(payload)).slice(0, 4), all.slice(-4));
    return { payload, ok, checksum: all.slice(-4) };
  }

  /* ---------- Base45 (RFC 9285) ---------- */
  const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function b45encode(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 2) {
      if (i + 1 < bytes.length) {
        let n = bytes[i] * 256 + bytes[i + 1];
        const c = n % 45; n = (n - c) / 45;
        const d = n % 45; const e = (n - d) / 45;
        out += B45[c] + B45[d] + B45[e];
      } else {
        const n = bytes[i];
        out += B45[n % 45] + B45[Math.floor(n / 45)];
      }
    }
    return out;
  }
  function b45decode(s) {
    const clean = s.replace(/[\r\n\t]/g, '');
    const vals = Array.from(clean, (c) => {
      const i = B45.indexOf(c);
      if (i < 0) throw new Error(`Base45 문자가 아닙니다: "${c}"`);
      return i;
    });
    if (vals.length % 3 === 1) throw new Error('Base45 길이가 올바르지 않습니다.');
    const out = [];
    for (let i = 0; i < vals.length; i += 3) {
      if (i + 2 < vals.length) {
        const n = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 2025;
        if (n > 0xffff) throw new Error('Base45 값이 범위를 벗어났습니다.');
        out.push(n >> 8, n & 255);
      } else {
        const n = vals[i] + vals[i + 1] * 45;
        if (n > 0xff) throw new Error('Base45 값이 범위를 벗어났습니다.');
        out.push(n);
      }
    }
    return new Uint8Array(out);
  }

  /* ---------- Ascii85 / Z85 ---------- */
  function a85encode(bytes, { wrap = true } = {}) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 4) {
      const chunk = bytes.subarray(i, i + 4);
      const n = chunk.length;
      let v = 0;
      for (let j = 0; j < 4; j++) v = v * 256 + (chunk[j] || 0);
      if (n === 4 && v === 0) { out += 'z'; continue; }
      const enc = [];
      for (let j = 0; j < 5; j++) { enc.unshift(String.fromCharCode((v % 85) + 33)); v = Math.floor(v / 85); }
      out += enc.slice(0, n + 1).join('');
    }
    return wrap ? `<~${out}~>` : out;
  }
  function a85decode(s) {
    let clean = s.replace(/\s/g, '');
    if (clean.startsWith('<~')) clean = clean.slice(2);
    if (clean.endsWith('~>')) clean = clean.slice(0, -2);
    const out = [];
    let group = [];
    const flush = (g, n) => {
      let v = 0;
      for (const c of g) v = v * 85 + (c - 33);
      if (v > 0xffffffff) throw new Error('Ascii85 그룹 값이 범위를 벗어났습니다.');
      out.push(...[(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].slice(0, n));
    };
    for (const ch of clean) {
      if (ch === 'z' && group.length === 0) { out.push(0, 0, 0, 0); continue; }
      const c = ch.charCodeAt(0);
      if (c < 33 || c > 117) throw new Error(`Ascii85 문자가 아닙니다: "${ch}"`);
      group.push(c);
      if (group.length === 5) { flush(group, 4); group = []; }
    }
    if (group.length === 1) throw new Error('Ascii85 마지막 그룹이 너무 짧습니다.');
    if (group.length) {
      const n = group.length - 1;
      while (group.length < 5) group.push(117);
      flush(group, n);
    }
    return new Uint8Array(out);
  }

  const Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  function z85encode(bytes) {
    if (bytes.length % 4) throw new Error(`Z85는 4바이트 배수만 인코딩할 수 있습니다. (현재 ${bytes.length}바이트)`);
    let out = '';
    for (let i = 0; i < bytes.length; i += 4) {
      let v = ((bytes[i] << 24) >>> 0) + (bytes[i + 1] << 16) + (bytes[i + 2] << 8) + bytes[i + 3];
      const enc = [];
      for (let j = 0; j < 5; j++) { enc.unshift(Z85[v % 85]); v = Math.floor(v / 85); }
      out += enc.join('');
    }
    return out;
  }
  function z85decode(s) {
    const clean = s.replace(/\s/g, '');
    if (clean.length % 5) throw new Error('Z85 문자열 길이는 5의 배수여야 합니다.');
    const out = [];
    for (let i = 0; i < clean.length; i += 5) {
      let v = 0;
      for (let j = 0; j < 5; j++) {
        const d = Z85.indexOf(clean[i + j]);
        if (d < 0) throw new Error(`Z85 문자가 아닙니다: "${clean[i + j]}"`);
        v = v * 85 + d;
      }
      if (v > 0xffffffff) throw new Error('Z85 값이 범위를 벗어났습니다.');
      out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
    }
    return new Uint8Array(out);
  }

  /* ---------- basE91 ---------- */
  const B91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
  function b91encode(bytes) {
    let b = 0, n = 0, out = '';
    for (const byte of bytes) {
      b |= byte << n; n += 8;
      if (n > 13) {
        let v = b & 8191;
        if (v > 88) { b >>>= 13; n -= 13; } else { v = b & 16383; b >>>= 14; n -= 14; }
        out += B91[v % 91] + B91[Math.floor(v / 91)];
      }
    }
    if (n) {
      out += B91[b % 91];
      if (n > 7 || b > 90) out += B91[Math.floor(b / 91)];
    }
    return out;
  }
  function b91decode(s) {
    let v = -1, b = 0, n = 0;
    const out = [];
    for (const c of s) {
      const d = B91.indexOf(c);
      if (d < 0) {
        if (/\s/.test(c)) continue;
        throw new Error(`basE91 문자가 아닙니다: "${c}"`);
      }
      if (v < 0) v = d;
      else {
        v += d * 91;
        b |= v << n;
        n += (v & 8191) > 88 ? 13 : 14;
        do { out.push(b & 255); b >>>= 8; n -= 8; } while (n > 7);
        v = -1;
      }
    }
    if (v > -1) out.push((b | (v << n)) & 255);
    return new Uint8Array(out);
  }

  Object.assign(DL.fn, {
    b32encode, b32decode, b58encode, b58decode, b62encode, b62decode, b58checkEncode, b58checkDecode,
    b45encode, b45decode, a85encode, a85decode, z85encode, z85decode, b91encode, b91decode,
    b36encode: (b) => baseXEncode(b, B36), b36decode: (s) => baseXDecode(s, B36, 'Base36', true),
  });

  const IN = fmtOption('inFmt', '원본 형식', 'text', ['text', 'hex', 'base64'], 'encode');

  DL.addCategory({
    id: 'base',
    name: 'Base 계열 인코딩',
    desc: 'Base64부터 Base91·Base45·Base58Check까지 — 바이너리를 텍스트로 옮기는 인코딩 11종',
    color: 'blue',
    tools: [
      {
        id: 'base64', name: 'Base64', short: 'RFC 4648 · URL-safe · MIME',
        desc: '3바이트를 4개의 문자로 바꾸는 가장 흔한 인코딩입니다. 디코딩 시 URL-safe(-, _) 문자, 줄바꿈, 누락된 패딩을 자동으로 처리합니다.',
        fileInput: true,
        options: [
          IN,
          { id: 'urlsafe', label: 'URL-safe (-, _)', type: 'checkbox', default: false, mode: 'encode' },
          { id: 'nopad', label: '패딩(=) 제거', type: 'checkbox', default: false, mode: 'encode' },
          { id: 'mime', label: 'MIME 76자 줄바꿈', type: 'checkbox', default: false, mode: 'encode' },
        ],
        encode: (s, o) => {
          const out = b64encode(readBytes(s, o.inFmt), o);
          return o.mime ? out.match(/.{1,76}/g).join('\r\n') : out;
        },
        decode: (s) => b64decode(DL.asText(s)),
      },
      {
        id: 'base32', name: 'Base32', short: 'RFC 4648 · OTP 시크릿',
        desc: 'A–Z와 2–7만 사용하는 인코딩입니다. 대소문자 구분이 없어 OTP 시크릿 키 등에 자주 쓰입니다.',
        options: [IN, { id: 'nopad', label: '패딩(=) 제거', type: 'checkbox', default: false, mode: 'encode' }],
        encode: (s, o) => b32encode(readBytes(s, o.inFmt), o),
        decode: (s) => b32decode(s),
      },
      {
        id: 'base58', name: 'Base58', short: '비트코인 알파벳',
        desc: '헷갈리기 쉬운 0, O, I, l을 뺀 58개 문자를 사용합니다. 비트코인 주소, IPFS CID 등에서 쓰입니다.',
        options: [IN],
        encode: (s, o) => b58encode(readBytes(s, o.inFmt)),
        decode: (s) => b58decode(s),
      },
      {
        id: 'base58check', name: 'Base58Check', short: 'Base58 + 4바이트 체크섬',
        desc: '데이터 뒤에 SHA-256을 두 번 적용한 해시의 앞 4바이트를 붙여 Base58로 인코딩합니다. 비트코인 주소와 WIF 키 형식입니다. 디코딩 시 체크섬을 검증합니다.',
        options: [{ ...IN, default: 'hex' }],
        encode: (s, o) => b58checkEncode(readBytes(s, o.inFmt)),
        decode: async (s) => {
          const { payload, ok, checksum } = await b58checkDecode(s.trim());
          return [
            `체크섬    ${ok ? '✓ 일치' : '✗ 불일치 — 데이터가 손상되었거나 Base58Check가 아닙니다'} (${toHex(checksum)})`,
            `버전 바이트 0x${toHex(payload.slice(0, 1))}${payload[0] === 0 ? ' (비트코인 P2PKH 주소)' : payload[0] === 5 ? ' (비트코인 P2SH 주소)' : payload[0] === 0x80 ? ' (WIF 개인키)' : ''}`,
            `페이로드  ${toHex(payload)}`,
            `길이      ${payload.length} B`,
          ].join('\n');
        },
      },
      {
        id: 'base62', name: 'Base62', short: '0–9 A–Z a–z 영숫자',
        desc: '기호 없이 영문 대소문자와 숫자만 사용합니다. 단축 URL, ID 생성 등 URL에 그대로 넣어야 할 때 많이 쓰입니다.',
        options: [IN],
        encode: (s, o) => b62encode(readBytes(s, o.inFmt)),
        decode: (s) => b62decode(s),
      },
      {
        id: 'base36', name: 'Base36', short: '0–9 a–z · 대소문자 무시',
        desc: '숫자와 소문자 알파벳만 사용합니다. 대소문자를 구분하지 않아 사람이 받아 적기 쉽습니다.',
        options: [IN],
        encode: (s, o) => DL.fn.b36encode(readBytes(s, o.inFmt)),
        decode: (s) => DL.fn.b36decode(s),
      },
      {
        id: 'base45', name: 'Base45', short: 'RFC 9285 · QR 코드',
        desc: 'QR 코드의 영숫자 모드에 맞춘 인코딩입니다. EU 디지털 코로나 증명서(EU DCC)에서 사용되어 알려졌습니다.',
        options: [IN],
        encode: (s, o) => b45encode(readBytes(s, o.inFmt)),
        decode: (s) => b45decode(s),
      },
      {
        id: 'base85', name: 'Ascii85', short: 'Base85 · PDF/PostScript',
        desc: '4바이트를 5개의 문자로 표현해 Base64보다 효율적입니다. PDF와 PostScript에서 사용하며 <~ ~> 구분자를 붙입니다.',
        options: [IN, { id: 'wrap', label: '<~ ~> 구분자 포함', type: 'checkbox', default: true, mode: 'encode' }],
        encode: (s, o) => a85encode(readBytes(s, o.inFmt), o),
        decode: (s) => a85decode(s),
      },
      {
        id: 'z85', name: 'Z85', short: 'ZeroMQ Base85',
        desc: 'ZeroMQ에서 정의한 Base85 변형입니다. 따옴표와 역슬래시를 피해 소스 코드에 넣기 쉽습니다. 입력은 4바이트 배수여야 합니다.',
        options: [{ ...IN, default: 'hex' }],
        encode: (s, o) => z85encode(readBytes(s, o.inFmt)),
        decode: (s) => z85decode(s),
      },
      {
        id: 'base91', name: 'basE91', short: 'Base64보다 약 20% 짧음',
        desc: '91개의 출력 가능한 ASCII 문자를 사용해 Base64보다 결과가 짧습니다. CTF에서 종종 등장합니다.',
        options: [IN],
        encode: (s, o) => b91encode(readBytes(s, o.inFmt)),
        decode: (s) => b91decode(s),
      },
      {
        id: 'hex', name: '16진수 (Hex)', short: 'Base16 · 바이트 ↔ 16진 문자열',
        desc: '각 바이트를 두 자리 16진수로 표현합니다(Base16). 디코딩 시 공백, 콜론, 0x, \\x 접두사를 모두 인식합니다.',
        fileInput: true,
        options: [
          {
            id: 'sep', label: '형식', type: 'select', default: 'space', mode: 'encode',
            choices: [['space', '공백 구분'], ['none', '붙여쓰기'], ['colon', '콜론(:)'], ['bsx', '\\x 접두사'], ['zerox', '0x 접두사']],
          },
          { id: 'upper', label: '대문자', type: 'checkbox', default: false, mode: 'encode' },
        ],
        encode: (s, o) => toHex(readBytes(s, 'text'), o.upper, { space: ' ', none: '', colon: ':', bsx: '\\x', zerox: '0x' }[o.sep]),
        decode: (s) => fromHex(DL.asText(s)),
      },
    ],
  });
})(globalThis.DecryptLab);
