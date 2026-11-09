/* Base 계열 › Base36 */
(function (DL) {
  'use strict';
  const { readBytes, baseXEncode, baseXDecode, B36, IN } = DL.kits.base;
  const b36encode = (b) => baseXEncode(b, B36);
  const b36decode = (s) => baseXDecode(s, B36, 'Base36', true);
  Object.assign(DL.fn, { b36encode, b36decode });

  DL.addTool('base', {
    id: 'base36', name: 'Base36', short: '0–9 a–z · 대소문자 무시',
    desc: '숫자와 소문자 알파벳만 사용합니다. 대소문자를 구분하지 않아 사람이 받아 적기 쉽습니다.',
    options: [IN],
    encode: (s, o) => b36encode(readBytes(s, o.inFmt)),
    decode: (s) => b36decode(s),
  });
})(globalThis.DecryptLab);
