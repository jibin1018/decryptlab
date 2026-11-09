/* 고전 암호 › ROT47 */
(function (DL) {
  'use strict';
  const { SYM } = DL.kits.classic;
  const rot47 = (s) => s.replace(/[!-~]/g, (ch) => String.fromCharCode(33 + ((ch.charCodeAt(0) - 33 + 47) % 94)));
  DL.fn.rot47 = rot47;

  DL.addTool('classic', {
    id: 'rot47', name: 'ROT47', short: 'ASCII 33–126 회전',
    desc: '알파벳뿐 아니라 숫자와 기호까지 포함한 94개 ASCII 문자를 47칸 회전합니다. 두 번 적용하면 원문입니다.',
    modes: SYM, encode: (s) => rot47(s),
  });
})(globalThis.DecryptLab);
