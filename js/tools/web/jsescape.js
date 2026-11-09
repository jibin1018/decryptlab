/* 웹·문자 인코딩 › JS·C 문자열 이스케이프 */
(function (DL) {
  'use strict';
  const { utf8, concat } = DL.kits.web;

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
  Object.assign(DL.fn, { jsEscape, jsUnescape });

  DL.addTool('web', {
    id: 'jsescape', name: 'JS·C 문자열 이스케이프', short: '\\n \\x41 \\u0041 \\101',
    desc: '소스 코드 문자열 리터럴의 이스케이프를 만들거나 풉니다. 셸코드나 악성 스크립트에 흔한 "\\xec\\x95\\x88" 같은 바이트 이스케이프도 UTF-8로 복원합니다.',
    options: [
      { id: 'format', label: '형식', type: 'select', default: 'js', mode: 'encode', choices: [['js', 'JS 문자열 (비ASCII → \\u)'], ['jsall', '모든 문자 \\uXXXX'], ['bytes', 'UTF-8 바이트 \\xHH (C/Python)']] },
      { id: 'xmode', label: '\\xHH 해석', type: 'select', default: 'byte', mode: 'decode', choices: [['byte', 'UTF-8 바이트 (C/Python)'], ['char', '문자 코드 (JS)']] },
    ],
    encode: (s, o) => jsEscape(s, o),
    decode: (s, o) => jsUnescape(s, o),
  });
})(globalThis.DecryptLab);
