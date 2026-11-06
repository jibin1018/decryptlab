/* 웹·문자 인코딩 */
(function (DL) {
  'use strict';
  const { utf8, utf8Decode, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat } = DL;

  /* ---------- URL ---------- */
  function urlEncode(s, { all = false, plus = false } = {}) {
    if (all) return Array.from(utf8(s), (b) => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
    let r = encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
    if (plus) r = r.replace(/%20/g, '+');
    return r;
  }
  function urlDecode(s, { plus = false } = {}) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '%' && /^[0-9a-fA-F]{2}$/.test(s.substr(i + 1, 2))) {
        out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2;
      } else if (c === '+' && plus) out.push(32);
      else {
        const cp = s.codePointAt(i);
        if (cp > 0xffff) i++;
        out.push(...utf8(String.fromCodePoint(cp)));
      }
    }
    return new Uint8Array(out);
  }

  /* ---------- HTML 엔티티 ---------- */
  const HTML_BASIC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function htmlEncode(s, { scope = 'basic', style = 'hex' } = {}) {
    const num = (cp) => (style === 'hex' ? `&#x${cp.toString(16).toUpperCase()};` : `&#${cp};`);
    let out = '';
    for (const ch of s) {
      const cp = ch.codePointAt(0);
      if (scope === 'all') out += num(cp);
      else if (HTML_BASIC[ch]) out += HTML_BASIC[ch];
      else if (scope === 'nonascii' && cp > 126) out += num(cp);
      else out += ch;
    }
    return out;
  }
  function htmlDecode(s) {
    if (typeof DOMParser !== 'undefined') {
      // DOMParser로 만든 문서는 스크립트를 실행하지 않는다.
      const doc = new DOMParser().parseFromString(`<!doctype html><body><textarea>${s.replace(/<\/textarea/gi, '&lt;/textarea')}</textarea>`, 'text/html');
      return doc.querySelector('textarea').value;
    }
    return s
      .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);?/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, (_, n) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' })[n]);
  }

  /* ---------- 유니코드 이스케이프 ---------- */
  function uniEncode(s, { format = 'u4', scope = 'nonascii' } = {}) {
    let out = '';
    for (const ch of s) {
      const cp = ch.codePointAt(0);
      if (scope === 'nonascii' && cp >= 32 && cp < 127) { out += ch; continue; }
      if (format === 'u4') for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0');
      else if (format === 'ubrace') out += `\\u{${cp.toString(16)}}`;
      else out += `U+${cp.toString(16).toUpperCase().padStart(4, '0')} `;
    }
    return format === 'uplus' ? out.trimEnd() : out;
  }
  function uniDecode(s) {
    return s.replace(
      /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|U\+([0-9a-fA-F]{4,6}) ?/g,
      (_, brace, u4, x2, plus) => {
        if (brace) return String.fromCodePoint(parseInt(brace, 16));
        if (u4) return String.fromCharCode(parseInt(u4, 16));
        if (x2) return String.fromCharCode(parseInt(x2, 16));
        return String.fromCodePoint(parseInt(plus, 16));
      }
    );
  }

  /* ---------- JavaScript / C 문자열 이스케이프 ---------- */
  const SIMPLE_ESC = { '\\': '\\\\', '"': '\\"', "'": "\\'", '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f', '\v': '\\v', '\0': '\\0' };
  function jsEscape(s, { format = 'js' } = {}) {
    if (format === 'bytes') return Array.from(utf8(s), (b) => '\\x' + b.toString(16).padStart(2, '0')).join('');
    let out = '';
    for (const ch of s) {
      const cp = ch.codePointAt(0);
      if (format === 'jsall') { for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0'); continue; }
      if (SIMPLE_ESC[ch]) out += SIMPLE_ESC[ch];
      else if (cp < 32 || cp === 127) out += '\\x' + cp.toString(16).padStart(2, '0');
      else if (cp > 126) for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0');
      else out += ch;
    }
    return out;
  }
  function jsUnescape(s, { xmode = 'byte' } = {}) {
    const chunks = [];
    let str = '';
    const flush = () => { if (str) { chunks.push(utf8(str)); str = ''; } };
    const SIMPLE = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0', '\\': '\\', '"': '"', "'": "'", '/': '/', '`': '`' };
    for (let i = 0; i < s.length; i++) {
      if (s[i] !== '\\' || i + 1 >= s.length) { str += s[i]; continue; }
      const n = s[i + 1];
      let m;
      if ((m = /^x([0-9a-fA-F]{2})/.exec(s.slice(i + 1)))) {
        const v = parseInt(m[1], 16);
        if (xmode === 'byte') { flush(); chunks.push(Uint8Array.of(v)); } else str += String.fromCharCode(v);
        i += 3;
      } else if ((m = /^u\{([0-9a-fA-F]{1,6})\}/.exec(s.slice(i + 1)))) {
        str += String.fromCodePoint(parseInt(m[1], 16)); i += m[0].length;
      } else if ((m = /^u([0-9a-fA-F]{4})/.exec(s.slice(i + 1)))) {
        str += String.fromCharCode(parseInt(m[1], 16)); i += 5;
      } else if ((m = /^([0-7]{1,3})/.exec(s.slice(i + 1))) && !(m[1] === '0' && !/[0-7]/.test(s[i + 2] || ''))) {
        const v = parseInt(m[1], 8) & 255;
        if (xmode === 'byte') { flush(); chunks.push(Uint8Array.of(v)); } else str += String.fromCharCode(v);
        i += m[1].length;
      } else if (SIMPLE[n] !== undefined) { str += SIMPLE[n]; i += 1; }
      else { str += n; i += 1; }
    }
    flush();
    return concat(...chunks);
  }

  /* ---------- UTF-16 / UTF-32 ---------- */
  function utfEncode(s, enc, bom) {
    const out = [];
    const push16 = (u) => (enc === 'utf16le' ? out.push(u & 255, u >> 8) : out.push(u >> 8, u & 255));
    const push32 = (c) => (enc === 'utf32le'
      ? out.push(c & 255, (c >> 8) & 255, (c >> 16) & 255, c >>> 24)
      : out.push(c >>> 24, (c >> 16) & 255, (c >> 8) & 255, c & 255));
    if (bom) (enc.startsWith('utf16') ? push16 : push32)(0xfeff);
    if (enc.startsWith('utf16')) for (let i = 0; i < s.length; i++) push16(s.charCodeAt(i));
    else for (const ch of s) push32(ch.codePointAt(0));
    return new Uint8Array(out);
  }
  function utfDecode(bytes, enc) {
    let b = bytes;
    if (enc === 'auto') {
      if (b[0] === 0xff && b[1] === 0xfe && b[2] === 0 && b[3] === 0) enc = 'utf32le';
      else if (b[0] === 0 && b[1] === 0 && b[2] === 0xfe && b[3] === 0xff) enc = 'utf32be';
      else if (b[0] === 0xff && b[1] === 0xfe) enc = 'utf16le';
      else if (b[0] === 0xfe && b[1] === 0xff) enc = 'utf16be';
      else {
        // BOM이 없으면 0x00 바이트 위치로 추정 (ASCII 텍스트의 UTF-16LE는 홀수 위치가 0)
        let evenZero = 0, oddZero = 0;
        for (let i = 0; i < b.length; i++) if (b[i] === 0) (i % 2 ? oddZero++ : evenZero++);
        enc = evenZero > oddZero ? 'utf16be' : 'utf16le';
      }
    }
    if (enc.startsWith('utf16')) {
      if (b.length % 2) throw new Error('UTF-16 데이터는 2바이트 배수여야 합니다.');
      let s = '';
      for (let i = 0; i < b.length; i += 2) s += String.fromCharCode(enc === 'utf16le' ? b[i] | (b[i + 1] << 8) : (b[i] << 8) | b[i + 1]);
      return { text: s.replace(/^﻿/, ''), enc };
    }
    if (b.length % 4) throw new Error('UTF-32 데이터는 4바이트 배수여야 합니다.');
    let s = '';
    for (let i = 0; i < b.length; i += 4) {
      const c = enc === 'utf32le'
        ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0
        : ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      if (c > 0x10ffff) throw new Error(`올바르지 않은 UTF-32 코드 포인트: 0x${c.toString(16)}`);
      s += String.fromCodePoint(c);
    }
    return { text: s.replace(/^﻿/, ''), enc };
  }

  /* ---------- Punycode (RFC 3492) / IDNA ---------- */
  const P = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, bias: 72, n: 128 };
  function adapt(delta, numPoints, first) {
    let k = 0;
    delta = first ? Math.floor(delta / P.damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((P.base - P.tMin) * P.tMax) >> 1; k += P.base) delta = Math.floor(delta / (P.base - P.tMin));
    return Math.floor(k + ((P.base - P.tMin + 1) * delta) / (delta + P.skew));
  }
  const digitChar = (d) => String.fromCharCode(d + 22 + 75 * (d < 26));
  const charDigit = (c) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : P.base);
  const threshold = (k, bias) => (k <= bias ? P.tMin : k >= bias + P.tMax ? P.tMax : k - bias);
  function punyEncode(str) {
    const cps = Array.from(str, (c) => c.codePointAt(0));
    let n = P.n, delta = 0, bias = P.bias;
    let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join('');
    const b = out.length;
    let h = b;
    if (b) out += '-';
    while (h < cps.length) {
      const m = Math.min(...cps.filter((c) => c >= n));
      delta += (m - n) * (h + 1);
      n = m;
      for (const c of cps) {
        if (c < n) delta++;
        if (c === n) {
          let q = delta;
          for (let k = P.base; ; k += P.base) {
            const t = threshold(k, bias);
            if (q < t) break;
            out += digitChar(t + ((q - t) % (P.base - t)));
            q = Math.floor((q - t) / (P.base - t));
          }
          out += digitChar(q);
          bias = adapt(delta, h + 1, h === b);
          delta = 0; h++;
        }
      }
      delta++; n++;
    }
    return out;
  }
  function punyDecode(input) {
    const out = [];
    let n = P.n, i = 0, bias = P.bias;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('Punycode 기본 문자 영역에 비ASCII 문자가 있습니다.');
      out.push(input.charCodeAt(j));
    }
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = P.base; ; k += P.base) {
        if (idx >= input.length) throw new Error('Punycode 입력이 중간에 끝났습니다.');
        const digit = charDigit(input.charCodeAt(idx++));
        if (digit >= P.base) throw new Error(`Punycode 문자가 아닙니다: "${input[idx - 1]}"`);
        i += digit * w;
        const t = threshold(k, bias);
        if (digit < t) break;
        w *= P.base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const idnToAscii = (domain) => domain.split('.').map((l) => (/[^\x00-\x7f]/.test(l) ? 'xn--' + punyEncode(l.toLowerCase()) : l)).join('.');
  const idnToUnicode = (domain) => domain.split('.').map((l) => (/^xn--/i.test(l) ? punyDecode(l.slice(4).toLowerCase()) : l)).join('.');

  /* ---------- Quoted-Printable ---------- */
  function qpEncode(s) {
    const bytes = utf8(s.replace(/\r?\n/g, '\n'));
    let out = '', line = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 10) { out += '\n'; line = 0; continue; }
      const nextIsEol = i + 1 >= bytes.length || bytes[i + 1] === 10;
      const literal = (b >= 33 && b <= 126 && b !== 61) || ((b === 32 || b === 9) && !nextIsEol);
      const tok = literal ? String.fromCharCode(b) : '=' + b.toString(16).toUpperCase().padStart(2, '0');
      if (line + tok.length > 75) { out += '=\n'; line = 0; }
      out += tok; line += tok.length;
    }
    return out;
  }
  function qpDecode(s) {
    const src = s.replace(/=\r?\n/g, '');
    const out = [];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === '=' && /^[0-9a-fA-F]{2}$/.test(src.substr(i + 1, 2))) {
        out.push(parseInt(src.substr(i + 1, 2), 16)); i += 2;
      } else {
        const cp = src.codePointAt(i);
        if (cp > 0xffff) i++;
        out.push(...utf8(String.fromCodePoint(cp)));
      }
    }
    return new Uint8Array(out);
  }

  /* ---------- MIME Encoded-Word (RFC 2047) ---------- */
  function mimeWordEncode(s, { enc = 'B' } = {}) {
    if (enc === 'B') return `=?UTF-8?B?${b64encode(utf8(s))}?=`;
    const q = Array.from(utf8(s), (b) => {
      if (b === 32) return '_';
      if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || '!*+-/'.includes(String.fromCharCode(b))) return String.fromCharCode(b);
      return '=' + b.toString(16).toUpperCase().padStart(2, '0');
    }).join('');
    return `=?UTF-8?Q?${q}?=`;
  }
  function mimeWordDecode(s) {
    const joined = s.replace(/\?=\s+=\?/g, '?==?');
    let found = false;
    const out = joined.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, data) => {
      found = true;
      let bytes;
      if (enc.toUpperCase() === 'B') bytes = b64decode(data);
      else bytes = qpDecode(data.replace(/_/g, ' '));
      try { return new TextDecoder(charset.replace(/\*.*$/, '').toLowerCase()).decode(bytes); }
      catch { throw new Error(`지원하지 않는 문자셋입니다: ${charset}`); }
    });
    if (!found) throw new Error('=?문자셋?B|Q?데이터?= 형식의 Encoded-Word를 찾지 못했습니다.');
    return out;
  }

  /* ---------- UUEncode ---------- */
  const uuChar = (v) => (v === 0 ? '`' : String.fromCharCode(v + 32));
  function uuEncode(bytes, name = 'data.bin') {
    const lines = [`begin 644 ${name}`];
    for (let i = 0; i < bytes.length; i += 45) {
      const chunk = bytes.subarray(i, i + 45);
      let line = uuChar(chunk.length);
      for (let j = 0; j < chunk.length; j += 3) {
        const a = chunk[j], b = chunk[j + 1] || 0, c = chunk[j + 2] || 0;
        line += uuChar(a >> 2) + uuChar(((a << 4) | (b >> 4)) & 63) + uuChar(((b << 2) | (c >> 6)) & 63) + uuChar(c & 63);
      }
      lines.push(line);
    }
    lines.push('`', 'end');
    return lines.join('\n');
  }
  function uuDecode(s) {
    const out = [];
    const lines = s.split(/\r?\n/);
    let started = !lines.some((l) => /^begin\s/.test(l));
    for (const line of lines) {
      if (!started) { if (/^begin\s/.test(line)) started = true; continue; }
      if (/^end\s*$/.test(line)) break;
      if (!line) continue;
      const n = (line.charCodeAt(0) - 32) & 63;
      if (!n) continue;
      const vals = Array.from(line.slice(1), (c) => (c.charCodeAt(0) - 32) & 63);
      const bytes = [];
      for (let j = 0; j + 3 < vals.length + 3 && bytes.length < n; j += 4) {
        const [a, b, c, d] = [vals[j] || 0, vals[j + 1] || 0, vals[j + 2] || 0, vals[j + 3] || 0];
        bytes.push(((a << 2) | (b >> 4)) & 255, ((b << 4) | (c >> 2)) & 255, ((c << 6) | d) & 255);
      }
      out.push(...bytes.slice(0, n));
    }
    return new Uint8Array(out);
  }

  /* ---------- 문자셋 해석 ---------- */
  const CHARSETS = [
    ['utf-8', 'UTF-8'], ['euc-kr', 'EUC-KR / CP949'], ['shift_jis', 'Shift_JIS'], ['euc-jp', 'EUC-JP'],
    ['gb18030', 'GB18030 / GBK'], ['big5', 'Big5'], ['windows-1252', 'Windows-1252'], ['iso-8859-1', 'ISO-8859-1'],
    ['koi8-r', 'KOI8-R'], ['windows-1251', 'Windows-1251'], ['utf-16le', 'UTF-16LE'], ['utf-16be', 'UTF-16BE'],
  ];
  function charsetDecode(bytes, cs) {
    const run = (c) => new TextDecoder(c).decode(bytes);
    if (cs !== 'all') return run(cs);
    return CHARSETS.map(([c, label]) => {
      let t;
      try { t = run(c); } catch { t = '(지원하지 않음)'; }
      const bad = (t.match(/�/g) || []).length;
      return `■ ${label}${bad ? `  — 깨진 문자 ${bad}개` : ''}\n${t}`;
    }).join('\n\n');
  }

  Object.assign(DL.fn, {
    urlEncode, urlDecode, htmlEncode, htmlDecode, uniEncode, uniDecode, jsEscape, jsUnescape,
    utfEncode, utfDecode, punyEncode, punyDecode, idnToAscii, idnToUnicode, qpEncode, qpDecode,
    mimeWordEncode, mimeWordDecode, uuEncode, uuDecode, charsetDecode,
  });

  DL.addCategory({
    id: 'web',
    name: '웹·문자 인코딩',
    desc: 'URL·HTML·JS 이스케이프부터 UTF-16, Punycode, 메일 제목 인코딩, EUC-KR 같은 문자셋까지',
    color: 'orange',
    tools: [
      {
        id: 'url', name: 'URL 인코딩', short: '퍼센트 인코딩 · Form 인코딩',
        desc: 'URL에 쓸 수 없는 문자를 %XX로 바꿉니다(RFC 3986). "공백 ↔ +"를 켜면 HTML 폼 전송 형식(application/x-www-form-urlencoded)이 됩니다.',
        options: [
          { id: 'all', label: '모든 문자 인코딩', type: 'checkbox', default: false, mode: 'encode' },
          { id: 'plus', label: '공백 ↔ + (Form)', type: 'checkbox', default: false },
        ],
        encode: (s, o) => urlEncode(s, o),
        decode: (s, o) => urlDecode(s, o),
      },
      {
        id: 'html', name: 'HTML·XML 엔티티', short: '&lt; &#x41; 이름/숫자 엔티티',
        desc: 'HTML·XML에서 특별한 의미를 가진 문자를 엔티티로 바꿉니다. 디코딩은 이름 엔티티(&amp;nbsp; 등)와 숫자 엔티티를 모두 지원합니다.',
        options: [
          {
            id: 'scope', label: '변환 범위', type: 'select', default: 'basic', mode: 'encode',
            choices: [['basic', '특수문자만 (& < > " \')'], ['nonascii', '특수문자 + 비ASCII'], ['all', '모든 문자']],
          },
          { id: 'style', label: '숫자 형식', type: 'select', default: 'hex', mode: 'encode', choices: [['hex', '16진 (&#x41;)'], ['dec', '10진 (&#65;)']] },
        ],
        encode: (s, o) => htmlEncode(s, o),
        decode: (s) => htmlDecode(s),
      },
      {
        id: 'unicode', name: '유니코드 이스케이프', short: '\\uXXXX · \\u{X} · U+XXXX',
        desc: '문자를 코드 포인트 이스케이프로 표현합니다(JSON 문자열의 \\uXXXX 포함). 디코딩은 여러 형식을 섞어 써도 처리합니다.',
        options: [
          { id: 'format', label: '형식', type: 'select', default: 'u4', mode: 'encode', choices: [['u4', '\\uXXXX (JS/JSON)'], ['ubrace', '\\u{X} (ES6)'], ['uplus', 'U+XXXX']] },
          { id: 'scope', label: '변환 범위', type: 'select', default: 'nonascii', mode: 'encode', choices: [['nonascii', '비ASCII만'], ['all', '모든 문자']] },
        ],
        encode: (s, o) => uniEncode(s, o),
        decode: (s) => uniDecode(s),
      },
      {
        id: 'jsescape', name: 'JS·C 문자열 이스케이프', short: '\\n \\x41 \\u0041 \\101',
        desc: '소스 코드 문자열 리터럴의 이스케이프를 만들거나 풉니다. 셸코드나 악성 스크립트에 흔한 "\\xec\\x95\\x88" 같은 바이트 이스케이프도 UTF-8로 복원합니다.',
        options: [
          { id: 'format', label: '형식', type: 'select', default: 'js', mode: 'encode', choices: [['js', 'JS 문자열 (비ASCII → \\u)'], ['jsall', '모든 문자 \\uXXXX'], ['bytes', 'UTF-8 바이트 \\xHH (C/Python)']] },
          { id: 'xmode', label: '\\xHH 해석', type: 'select', default: 'byte', mode: 'decode', choices: [['byte', 'UTF-8 바이트 (C/Python)'], ['char', '문자 코드 (JS)']] },
        ],
        encode: (s, o) => jsEscape(s, o),
        decode: (s, o) => jsUnescape(s, o),
      },
      {
        id: 'utf16', name: 'UTF-16 · UTF-32', short: 'LE/BE · BOM 처리',
        desc: '텍스트를 UTF-16/UTF-32 바이트(16진수)로 바꾸거나 되돌립니다. Windows API 문자열, PowerShell -EncodedCommand(UTF-16LE+Base64) 분석에 유용합니다.',
        options: [
          { id: 'enc', label: '인코딩', type: 'select', default: 'utf16le', choices: [['auto', '자동 (BOM/널 바이트)'], ['utf16le', 'UTF-16LE'], ['utf16be', 'UTF-16BE'], ['utf32le', 'UTF-32LE'], ['utf32be', 'UTF-32BE']] },
          { id: 'bom', label: 'BOM 포함', type: 'checkbox', default: false, mode: 'encode' },
          fmtOption('fmt', '바이트 형식', 'hex', ['hex', 'base64']),
        ],
        encode: (s, o) => {
          const b = utfEncode(s, o.enc === 'auto' ? 'utf16le' : o.enc, o.bom);
          return o.fmt === 'base64' ? b64encode(b) : toHex(b, false, ' ');
        },
        decode: (s, o) => {
          const r = utfDecode(readBytes(s, o.fmt), o.enc);
          return o.enc === 'auto' ? `[${r.enc.toUpperCase()}로 판단]\n${r.text}` : r.text;
        },
      },
      {
        id: 'punycode', name: 'Punycode · IDN', short: '한국.kr ↔ xn--3e0b707e.kr',
        desc: '국제화 도메인(IDN)을 DNS가 이해하는 ASCII(xn--) 형태로 바꿉니다. 피싱 도메인(동형 문자 공격) 확인에 활용할 수 있습니다.',
        options: [{ id: 'domain', label: '도메인 단위 (xn-- 접두사)', type: 'checkbox', default: true }],
        encode: (s, o) => s.split(/\r?\n/).map((l) => (o.domain ? idnToAscii(l.trim()) : punyEncode(l.trim()))).join('\n'),
        decode: (s, o) => s.split(/\r?\n/).map((l) => (o.domain ? idnToUnicode(l.trim()) : punyDecode(l.trim()))).join('\n'),
      },
      {
        id: 'mimeword', name: 'MIME Encoded-Word', short: '=?UTF-8?B?…?= 메일 제목',
        desc: '이메일 제목이나 보낸 사람 이름에 쓰이는 RFC 2047 인코딩입니다. 디코딩은 EUC-KR, ISO-2022-JP 등 다른 문자셋도 처리합니다.',
        options: [{ id: 'enc', label: '방식', type: 'select', default: 'B', mode: 'encode', choices: [['B', 'B (Base64)'], ['Q', 'Q (Quoted-Printable)']] }],
        encode: (s, o) => mimeWordEncode(s, o),
        decode: (s) => mimeWordDecode(s),
      },
      {
        id: 'qp', name: 'Quoted-Printable', short: '이메일 본문 인코딩',
        desc: '대부분의 ASCII는 그대로 두고 나머지 바이트만 =XX로 바꾸는 이메일(MIME) 인코딩입니다. 한 줄은 76자를 넘지 않습니다.',
        encode: (s) => qpEncode(s),
        decode: (s) => qpDecode(s),
      },
      {
        id: 'uuencode', name: 'UUEncode', short: 'begin 644 … end',
        desc: '유닉스 시절부터 쓰인 바이너리→텍스트 인코딩입니다. 오래된 메일 첨부나 일부 악성코드 페이로드에서 볼 수 있습니다.',
        fileInput: true,
        options: [{ id: 'name', label: '파일 이름', type: 'text', default: 'data.bin', mode: 'encode' }],
        encode: (s, o) => uuEncode(readBytes(s, 'text'), o.name || 'data.bin'),
        decode: (s) => uuDecode(DL.asText(s)),
      },
      {
        id: 'charset', name: '문자셋 해석', short: 'EUC-KR · Shift_JIS 등 깨진 글자 복원',
        desc: '바이트를 여러 문자셋으로 해석해 봅니다. "怨좉컼" 같이 깨진 한글은 EUC-KR 바이트를 다른 문자셋으로 읽은 경우가 많습니다.',
        modes: [{ id: 'decode', label: '해석', inLabel: '바이트', placeholder: '16진수 바이트 (예: c7 d1 b1 db)' }],
        fileInput: true,
        options: [
          fmtOption('fmt', '입력 형식', 'hex', ['hex', 'base64']),
          { id: 'cs', label: '문자셋', type: 'select', default: 'all', choices: [['all', '모두 비교'], ...CHARSETS] },
        ],
        decode: (s, o) => charsetDecode(readBytes(s, o.fmt), o.cs),
      },
    ],
  });
})(globalThis.DecryptLab);
