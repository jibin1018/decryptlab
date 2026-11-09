/* Base 계열 › Base62 */
(function (DL) {
  'use strict';
  const { readBytes, baseXEncode, baseXDecode, B62, IN } = DL.kits.base;
  const b62encode = (b) => baseXEncode(b, B62);
  const b62decode = (s) => baseXDecode(s, B62, 'Base62');
  Object.assign(DL.fn, { b62encode, b62decode });

  DL.addTool('base', {
    id: 'base62', name: 'Base62', short: '0–9 A–Z a–z 영숫자',
    desc: '기호 없이 영문 대소문자와 숫자만 사용합니다. 단축 URL, ID 생성 등 URL에 그대로 넣어야 할 때 많이 쓰입니다.',
    options: [IN],
    encode: (s, o) => b62encode(readBytes(s, o.inFmt)),
    decode: (s) => b62decode(s),
  });
})(globalThis.DecryptLab);
