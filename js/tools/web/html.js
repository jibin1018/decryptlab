/* 웹·문자 인코딩 › HTML·XML 엔티티 */
(function (DL) {
  'use strict';

  const HTML_BASIC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function htmlEncode(s, { scope = 'basic', style = 'hex' } = {}) {
    const num = (cp) => (style === 'hex' ? `&#x${cp.toString(16).toUpperCase()};` : `&#${cp};`);
    let out = '';
    for (const ch of s) {
      const cp = ch.codePointAt(0);
      if (scope === 'all') out += num(cp);
      else if (HTML_BASIC[ch]) out += HTML_BASIC[ch];
      else if (scope === 'nonascii' && cp > 126) out += num(cp);
      else out += ch;
    }
    return out;
  }
  function htmlDecode(s) {
    if (typeof DOMParser !== 'undefined') {
      // DOMParser로 만든 문서는 스크립트를 실행하지 않는다.
      const doc = new DOMParser().parseFromString(`<!doctype html><body><textarea>${s.replace(/<\/textarea/gi, '&lt;/textarea')}</textarea>`, 'text/html');
      return doc.querySelector('textarea').value;
    }
    return s
      .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);?/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, (_, n) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' })[n]);
  }
  Object.assign(DL.fn, { htmlEncode, htmlDecode });

  DL.addTool('web', {
    id: 'html', name: 'HTML·XML 엔티티', short: '&lt; &#x41; 이름/숫자 엔티티',
    desc: 'HTML·XML에서 특별한 의미를 가진 문자를 엔티티로 바꿉니다. 디코딩은 이름 엔티티(&amp;nbsp; 등)와 숫자 엔티티를 모두 지원합니다.',
    options: [
      {
        id: 'scope', label: '변환 범위', type: 'select', default: 'basic', mode: 'encode',
        choices: [['basic', '특수문자만 (& < > " \')'], ['nonascii', '특수문자 + 비ASCII'], ['all', '모든 문자']],
      },
      { id: 'style', label: '숫자 형식', type: 'select', default: 'hex', mode: 'encode', choices: [['hex', '16진 (&#x41;)'], ['dec', '10진 (&#65;)']] },
    ],
    encode: (s, o) => htmlEncode(s, o),
    decode: (s) => htmlDecode(s),
  });
})(globalThis.DecryptLab);
