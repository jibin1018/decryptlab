/* 웹·문자 인코딩 › URL 인코딩 */
(function (DL) {
  'use strict';
  const { utf8 } = DL.kits.web;

  function urlEncode(s, { all = false, plus = false } = {}) {
    if (all) return Array.from(utf8(s), (b) => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
    let r = encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
    if (plus) r = r.replace(/%20/g, '+');
    return r;
  }
  function urlDecode(s, { plus = false } = {}) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '%' && /^[0-9a-fA-F]{2}$/.test(s.substr(i + 1, 2))) {
        out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2;
      } else if (c === '+' && plus) out.push(32);
      else {
        const cp = s.codePointAt(i);
        if (cp > 0xffff) i++;
        out.push(...utf8(String.fromCodePoint(cp)));
      }
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { urlEncode, urlDecode });

  DL.addTool('web', {
    id: 'url', name: 'URL 인코딩', short: '퍼센트 인코딩 · Form 인코딩',
    desc: 'URL에 쓸 수 없는 문자를 %XX로 바꿉니다(RFC 3986). "공백 ↔ +"를 켜면 HTML 폼 전송 형식(application/x-www-form-urlencoded)이 됩니다.',
    options: [
      { id: 'all', label: '모든 문자 인코딩', type: 'checkbox', default: false, mode: 'encode' },
      { id: 'plus', label: '공백 ↔ + (Form)', type: 'checkbox', default: false },
    ],
    encode: (s, o) => urlEncode(s, o),
    decode: (s, o) => urlDecode(s, o),
  });
})(globalThis.DecryptLab);
