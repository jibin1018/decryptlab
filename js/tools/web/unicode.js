/* 웹·문자 인코딩 › 유니코드 이스케이프 */
(function (DL) {
  'use strict';

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
  Object.assign(DL.fn, { uniEncode, uniDecode });

  DL.addTool('web', {
    id: 'unicode', name: '유니코드 이스케이프', short: '\\uXXXX · \\u{X} · U+XXXX',
    desc: '문자를 코드 포인트 이스케이프로 표현합니다(JSON 문자열의 \\uXXXX 포함). 디코딩은 여러 형식을 섞어 써도 처리합니다.',
    options: [
      { id: 'format', label: '형식', type: 'select', default: 'u4', mode: 'encode', choices: [['u4', '\\uXXXX (JS/JSON)'], ['ubrace', '\\u{X} (ES6)'], ['uplus', 'U+XXXX']] },
      { id: 'scope', label: '변환 범위', type: 'select', default: 'nonascii', mode: 'encode', choices: [['nonascii', '비ASCII만'], ['all', '모든 문자']] },
    ],
    encode: (s, o) => uniEncode(s, o),
    decode: (s) => uniDecode(s),
  });
})(globalThis.DecryptLab);
