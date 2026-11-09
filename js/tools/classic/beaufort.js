/* 고전 암호 › Beaufort 암호 */
(function (DL) {
  'use strict';
  const { mod, mapLetters, keyStream, SYM } = DL.kits.classic;

  function beaufort(s, key) {
    const k = keyStream(key);
    let j = 0;
    return mapLetters(s, (x) => mod(k[j++ % k.length] - x, 26));
  }

  DL.addTool('classic', {
    id: 'beaufort', name: 'Beaufort 암호', short: 'C = K − P (대칭)',
    desc: '비즈네르의 변형으로, 키에서 평문을 뺍니다. 암호화와 복호화가 같은 연산입니다.',
    modes: SYM,
    options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
    encode: (s, o) => beaufort(s, o.key),
  });
})(globalThis.DecryptLab);
