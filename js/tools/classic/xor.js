/* 고전 암호 › XOR */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex, ENC_DEC } = DL.kits.classic;

  function xorBytes(data, key) {
    if (!key.length) throw new Error('XOR 키를 입력하세요.');
    return data.map((b, i) => b ^ key[i % key.length]);
  }
  const xorKey = (o) => (o.keyType === 'hex' ? fromHex(o.key || '') : utf8(o.key || ''));
  DL.fn.xorBytes = xorBytes;

  DL.addTool('classic', {
    id: 'xor', name: 'XOR', short: '반복 키 XOR · Hex 출력',
    desc: '입력 바이트를 키와 반복 XOR합니다. 결과는 바이너리이므로 암호화 출력과 복호화 입력은 16진수를 사용합니다. 키를 모르면 "바이너리 분석 → XOR 전수 조사"를 사용하세요.',
    modes: ENC_DEC,
    options: [
      { id: 'key', label: '키', type: 'text', default: 'secret' },
      { id: 'keyType', label: '키 형식', type: 'select', default: 'text', choices: [['text', '텍스트'], ['hex', '16진수']] },
    ],
    encode: (s, o) => toHex(xorBytes(utf8(s), xorKey(o)), false, ' '),
    decode: (s, o) => xorBytes(fromHex(s), xorKey(o)),
  });
})(globalThis.DecryptLab);
