/* 진법·데이터 표현 › 10진수 바이트 */
(function (DL) {
  'use strict';
  const { utf8, SEP_OPTION, radixEncode, radixDecode } = DL.kits.radix;

  DL.addTool('radix', {
    id: 'decimal', name: '10진수 바이트', short: '0–255 값 목록 · ASCII Decimal',
    desc: 'UTF-8 바이트를 0–255 사이의 10진수로 표현합니다. 바이트 배열을 그대로 붙여 넣을 때 유용합니다.',
    options: [{ ...SEP_OPTION, default: 'comma' }],
    encode: (s, o) => radixEncode(utf8(s), 10, 0, o.sep),
    decode: (s) => radixDecode(s, 10),
  });
})(globalThis.DecryptLab);
