/* 고전 암호 › 카이사르 암호 */
(function (DL) {
  'use strict';
  const { caesar, ENC_DEC } = DL.kits.classic;

  DL.addTool('classic', {
    id: 'caesar', name: '카이사르 암호', short: '알파벳 시프트 · 전수 조사',
    desc: '알파벳을 일정한 칸만큼 밀어 치환합니다. 키를 모를 때는 "모든 시프트 보기"로 25가지 결과를 한 번에 확인하세요.',
    modes: ENC_DEC,
    options: [
      { id: 'shift', label: '시프트', type: 'number', default: 3, min: -25, max: 25 },
      { id: 'brute', label: '모든 시프트 보기', type: 'checkbox', default: false, mode: 'decode' },
    ],
    encode: (s, o) => caesar(s, Number(o.shift) || 0),
    decode: (s, o) => (o.brute
      ? Array.from({ length: 25 }, (_, i) => `ROT${String(i + 1).padStart(2, '0')}  ${caesar(s, -(i + 1))}`).join('\n')
      : caesar(s, -(Number(o.shift) || 0))),
  });
})(globalThis.DecryptLab);
