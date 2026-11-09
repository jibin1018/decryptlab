/* 진법·데이터 표현 › 8진수 */
(function (DL) {
  'use strict';
  const { utf8, SEP_OPTION, radixEncode, radixDecode } = DL.kits.radix;

  DL.addTool('radix', {
    id: 'octal', name: '8진수', short: '3자리 단위',
    desc: 'UTF-8 바이트를 3자리 8진수로 표현합니다.',
    options: [SEP_OPTION],
    encode: (s, o) => radixEncode(utf8(s), 8, 3, o.sep),
    decode: (s) => radixDecode(s, 8),
  });
})(globalThis.DecryptLab);
