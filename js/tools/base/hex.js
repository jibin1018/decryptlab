/* Base 계열 › 16진수 (Hex) */
(function (DL) {
  'use strict';
  const { toHex, fromHex, readBytes, asText } = DL.kits.base;

  DL.addTool('base', {
    id: 'hex', name: '16진수 (Hex)', short: 'Base16 · 바이트 ↔ 16진 문자열',
    desc: '각 바이트를 두 자리 16진수로 표현합니다(Base16). 디코딩 시 공백, 콜론, 0x, \\x 접두사를 모두 인식합니다.',
    fileInput: true,
    options: [
      {
        id: 'sep', label: '형식', type: 'select', default: 'space', mode: 'encode',
        choices: [['space', '공백 구분'], ['none', '붙여쓰기'], ['colon', '콜론(:)'], ['bsx', '\\x 접두사'], ['zerox', '0x 접두사']],
      },
      { id: 'upper', label: '대문자', type: 'checkbox', default: false, mode: 'encode' },
    ],
    encode: (s, o) => toHex(readBytes(s, 'text'), o.upper, { space: ' ', none: '', colon: ':', bsx: '\\x', zerox: '0x' }[o.sep]),
    decode: (s) => fromHex(asText(s)),
  });
})(globalThis.DecryptLab);
