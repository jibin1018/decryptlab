/* 웹·문자 인코딩 › Quoted-Printable (qpEncode/qpDecode는 _web.js의 공유 헬퍼) */
(function (DL) {
  'use strict';
  const { qpEncode, qpDecode } = DL.kits.web;

  DL.addTool('web', {
    id: 'qp', name: 'Quoted-Printable', short: '이메일 본문 인코딩',
    desc: '대부분의 ASCII는 그대로 두고 나머지 바이트만 =XX로 바꾸는 이메일(MIME) 인코딩입니다. 한 줄은 76자를 넘지 않습니다.',
    encode: (s) => qpEncode(s),
    decode: (s) => qpDecode(s),
  });
})(globalThis.DecryptLab);
