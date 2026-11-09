/* Base 계열 › Base64 */
(function (DL) {
  'use strict';
  const { toHex, fromHex, b64encode, b64decode, readBytes, asText, IN } = DL.kits.base;

  DL.addTool('base', {
    id: 'base64', name: 'Base64', short: 'RFC 4648 · URL-safe · MIME',
    desc: '3바이트를 4개의 문자로 바꾸는 가장 흔한 인코딩입니다. 디코딩 시 URL-safe(-, _) 문자, 줄바꿈, 누락된 패딩을 자동으로 처리합니다.',
    fileInput: true,
    options: [
      IN,
      { id: 'urlsafe', label: 'URL-safe (-, _)', type: 'checkbox', default: false, mode: 'encode' },
      { id: 'nopad', label: '패딩(=) 제거', type: 'checkbox', default: false, mode: 'encode' },
      { id: 'mime', label: 'MIME 76자 줄바꿈', type: 'checkbox', default: false, mode: 'encode' },
    ],
    encode: (s, o) => {
      const out = b64encode(readBytes(s, o.inFmt), o);
      return o.mime ? out.match(/.{1,76}/g).join('\r\n') : out;
    },
    decode: (s) => b64decode(asText(s)),
  });
})(globalThis.DecryptLab);
