/* 고전 암호 › Atbash */
(function (DL) {
  'use strict';
  const { mapLetters, SYM } = DL.kits.classic;
  const atbash = (s) => mapLetters(s, (x) => 25 - x);
  DL.fn.atbash = atbash;

  DL.addTool('classic', {
    id: 'atbash', name: 'Atbash', short: 'A↔Z 거울 치환',
    desc: 'A는 Z로, B는 Y로 — 알파벳을 거꾸로 대응시키는 고대 히브리 암호입니다.',
    modes: SYM, encode: (s) => atbash(s),
  });
})(globalThis.DecryptLab);
