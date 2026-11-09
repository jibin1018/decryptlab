/* 웹·문자 인코딩 — 카테고리 셸 + 공유 헬퍼 (DL.kits.web) */
(function (DL) {
  'use strict';
  const { utf8, utf8Decode, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat, asText } = DL;

  /* ---------- Quoted-Printable (qp 도구 + MIME Encoded-Word가 공유) ---------- */
  function qpEncode(s) {
    const bytes = utf8(s.replace(/\r?\n/g, '\n'));
    let out = '', line = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 10) { out += '\n'; line = 0; continue; }
      const nextIsEol = i + 1 >= bytes.length || bytes[i + 1] === 10;
      const literal = (b >= 33 && b <= 126 && b !== 61) || ((b === 32 || b === 9) && !nextIsEol);
      const tok = literal ? String.fromCharCode(b) : '=' + b.toString(16).toUpperCase().padStart(2, '0');
      if (line + tok.length > 75) { out += '=\n'; line = 0; }
      out += tok; line += tok.length;
    }
    return out;
  }
  function qpDecode(s) {
    const src = s.replace(/=\r?\n/g, '');
    const out = [];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === '=' && /^[0-9a-fA-F]{2}$/.test(src.substr(i + 1, 2))) {
        out.push(parseInt(src.substr(i + 1, 2), 16)); i += 2;
      } else {
        const cp = src.codePointAt(i);
        if (cp > 0xffff) i++;
        out.push(...utf8(String.fromCodePoint(cp)));
      }
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { qpEncode, qpDecode });

  DL.kits.web = { utf8, utf8Decode, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat, asText, qpEncode, qpDecode };

  DL.addCategory({
    id: 'web',
    name: '웹·문자 인코딩',
    desc: 'URL·HTML·JS 이스케이프부터 UTF-16, Punycode, 메일 제목 인코딩, EUC-KR 같은 문자셋까지',
    color: 'orange',
    tools: [],
  });
})(globalThis.DecryptLab);
