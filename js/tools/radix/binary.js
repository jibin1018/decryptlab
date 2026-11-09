/* 진법·데이터 표현 › 2진수 */
(function (DL) {
  'use strict';
  const { utf8, SEP_OPTION, radixEncode, radixDecode } = DL.kits.radix;

  DL.addTool('radix', {
    id: 'binary', name: '2진수', short: '8비트 단위 · ASCII Binary',
    desc: 'UTF-8 바이트를 8자리 2진수로 표현합니다. 디코딩 시 구분자 없이 이어 붙인 비트열도 8자리씩 나눠 처리합니다.',
    options: [SEP_OPTION],
    encode: (s, o) => radixEncode(utf8(s), 2, 8, o.sep),
    decode: (s) => radixDecode(s, 2),
  });
})(globalThis.DecryptLab);
