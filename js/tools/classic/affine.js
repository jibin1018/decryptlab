/* 고전 암호 › Affine 암호 */
(function (DL) {
  'use strict';
  const { mod, mapLetters, modInv, ENC_DEC } = DL.kits.classic;

  function affine(s, a, b, dir) {
    a = Number(a); b = Number(b);
    const inv = modInv(a, 26);
    if (inv === null) throw new Error(`a=${a}은(는) 26과 서로소가 아니라 복호화할 수 없습니다. (가능: 1,3,5,7,9,11,15,17,19,21,23,25)`);
    return mapLetters(s, (x) => (dir > 0 ? mod(a * x + b, 26) : mod(inv * (x - b), 26)));
  }

  DL.addTool('classic', {
    id: 'affine', name: 'Affine 암호', short: 'E(x) = (a·x + b) mod 26',
    desc: '곱셈과 덧셈을 결합한 단일 치환 암호입니다. a는 26과 서로소여야 복호화할 수 있습니다.',
    modes: ENC_DEC,
    options: [{ id: 'a', label: 'a', type: 'number', default: 5, min: 1, max: 25 }, { id: 'b', label: 'b', type: 'number', default: 8, min: 0, max: 25 }],
    encode: (s, o) => affine(s, o.a, o.b, 1),
    decode: (s, o) => affine(s, o.a, o.b, -1),
  });
})(globalThis.DecryptLab);
