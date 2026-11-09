/* Base 계열 › Base58 */
(function (DL) {
  'use strict';
  const { readBytes, b58encode, b58decode, IN } = DL.kits.base;

  DL.addTool('base', {
    id: 'base58', name: 'Base58', short: '비트코인 알파벳',
    desc: '헷갈리기 쉬운 0, O, I, l을 뺀 58개 문자를 사용합니다. 비트코인 주소, IPFS CID 등에서 쓰입니다.',
    options: [IN],
    encode: (s, o) => b58encode(readBytes(s, o.inFmt)),
    decode: (s) => b58decode(s),
  });
})(globalThis.DecryptLab);
