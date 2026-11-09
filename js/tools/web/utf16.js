/* 웹·문자 인코딩 › UTF-16 · UTF-32 */
(function (DL) {
  'use strict';
  const { toHex, b64encode, readBytes, fmtOption } = DL.kits.web;

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
  Object.assign(DL.fn, { utfEncode, utfDecode });

  DL.addTool('web', {
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
  });
})(globalThis.DecryptLab);
