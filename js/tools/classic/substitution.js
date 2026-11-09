/* 고전 암호 › 단일 치환 암호 */
(function (DL) {
  'use strict';
  const { A, mapLetters, ENC_DEC } = DL.kits.classic;

  function substitution(s, key, dir) {
    const k = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (k.length !== 26 || new Set(k).size !== 26) throw new Error('키는 A–Z가 한 번씩 모두 들어간 26글자여야 합니다.');
    return mapLetters(s, (x) => (dir > 0 ? k.charCodeAt(x) - 65 : k.indexOf(A[x])));
  }

  DL.addTool('classic', {
    id: 'substitution', name: '단일 치환 암호', short: '26글자 치환 알파벳',
    desc: 'A–Z를 임의의 순서로 섞은 치환 알파벳으로 한 글자씩 바꿉니다. 빈도 분석으로 풀 수 있는 대표적인 암호입니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '치환 알파벳', type: 'text', default: 'QWERTYUIOPASDFGHJKLZXCVBNM', wide: true }],
    encode: (s, o) => substitution(s, o.key, 1),
    decode: (s, o) => substitution(s, o.key, -1),
  });
})(globalThis.DecryptLab);
