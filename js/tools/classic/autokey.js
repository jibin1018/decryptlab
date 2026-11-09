/* 고전 암호 › Autokey 암호 */
(function (DL) {
  'use strict';
  const { mod, mapLetters, keyStream, ENC_DEC } = DL.kits.classic;

  function autokey(s, key, dir) {
    const stream = keyStream(key);
    let j = 0;
    return mapLetters(s, (x) => {
      const out = mod(x + dir * stream[j++], 26);
      stream.push(dir > 0 ? x : out); // 키 스트림은 평문으로 이어진다
      return out;
    });
  }

  DL.addTool('classic', {
    id: 'autokey', name: 'Autokey 암호', short: '평문이 키 스트림이 됨',
    desc: '키워드 뒤에 평문 자체를 이어 붙여 키 스트림으로 씁니다. 키가 반복되지 않아 비즈네르의 키 길이 분석이 통하지 않습니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
    encode: (s, o) => autokey(s, o.key, 1),
    decode: (s, o) => autokey(s, o.key, -1),
  });
})(globalThis.DecryptLab);
