/* 고전 암호 › 비즈네르 암호 */
(function (DL) {
  'use strict';
  const { vigenere, ENC_DEC } = DL.kits.classic;

  DL.addTool('classic', {
    id: 'vigenere', name: '비즈네르 암호', short: '키워드 다중 치환',
    desc: '키워드의 각 글자만큼 번갈아 시프트하는 다중 치환 암호입니다. 영문자가 아닌 문자는 그대로 두고 키도 넘기지 않습니다. 키를 모르면 "빈도 분석" 도구를 사용하세요.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
    encode: (s, o) => vigenere(s, o.key, 1),
    decode: (s, o) => vigenere(s, o.key, -1),
  });
})(globalThis.DecryptLab);
