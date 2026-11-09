/* 진법·데이터 표현 › 코드 포인트 */
(function (DL) {
  'use strict';

  DL.addTool('radix', {
    id: 'codepoint', name: '코드 포인트', short: '문자 단위 10진/16진',
    desc: '바이트가 아니라 문자 하나하나의 유니코드 번호를 보여줍니다. 한글 "가"는 44032(0xAC00)입니다.',
    options: [{ id: 'base', label: '진법', type: 'select', default: '10', mode: 'encode', choices: [['10', '10진수'], ['16', '16진수 (0x)']] }],
    encode: (s, o) => Array.from(s, (ch) => {
      const cp = ch.codePointAt(0);
      return o.base === '16' ? '0x' + cp.toString(16).toUpperCase() : String(cp);
    }).join(' '),
    decode: (s) => s.trim().split(/[\s,;]+/).filter(Boolean).map((t) => {
      const v = /^(0x|u\+)/i.test(t) ? parseInt(t.slice(2), 16) : parseInt(t, 10);
      if (!Number.isFinite(v) || v < 0 || v > 0x10ffff) throw new Error(`올바르지 않은 코드 포인트: "${t}"`);
      return String.fromCodePoint(v);
    }).join(''),
  });
})(globalThis.DecryptLab);
