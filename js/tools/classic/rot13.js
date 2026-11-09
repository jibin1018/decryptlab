/* 고전 암호 › ROT13 */
(function (DL) {
  'use strict';
  const { caesar, SYM } = DL.kits.classic;

  DL.addTool('classic', {
    id: 'rot13', name: 'ROT13', short: '13칸 시프트 (대칭)',
    desc: '알파벳을 13칸 미는 카이사르 암호의 특수형입니다. 두 번 적용하면 원문으로 돌아옵니다.',
    modes: SYM, encode: (s) => caesar(s, 13),
  });
})(globalThis.DecryptLab);
