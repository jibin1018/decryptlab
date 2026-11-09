/* 웹·문자 인코딩 › MIME Encoded-Word (RFC 2047) */
(function (DL) {
  'use strict';
  const { utf8, b64encode, b64decode, qpDecode } = DL.kits.web;

  function mimeWordEncode(s, { enc = 'B' } = {}) {
    if (enc === 'B') return `=?UTF-8?B?${b64encode(utf8(s))}?=`;
    const q = Array.from(utf8(s), (b) => {
      if (b === 32) return '_';
      if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || '!*+-/'.includes(String.fromCharCode(b))) return String.fromCharCode(b);
      return '=' + b.toString(16).toUpperCase().padStart(2, '0');
    }).join('');
    return `=?UTF-8?Q?${q}?=`;
  }
  function mimeWordDecode(s) {
    const joined = s.replace(/\?=\s+=\?/g, '?==?');
    let found = false;
    const out = joined.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, data) => {
      found = true;
      let bytes;
      if (enc.toUpperCase() === 'B') bytes = b64decode(data);
      else bytes = qpDecode(data.replace(/_/g, ' '));
      try { return new TextDecoder(charset.replace(/\*.*$/, '').toLowerCase()).decode(bytes); }
      catch { throw new Error(`지원하지 않는 문자셋입니다: ${charset}`); }
    });
    if (!found) throw new Error('=?문자셋?B|Q?데이터?= 형식의 Encoded-Word를 찾지 못했습니다.');
    return out;
  }
  Object.assign(DL.fn, { mimeWordEncode, mimeWordDecode });

  DL.addTool('web', {
    id: 'mimeword', name: 'MIME Encoded-Word', short: '=?UTF-8?B?…?= 메일 제목',
    desc: '이메일 제목이나 보낸 사람 이름에 쓰이는 RFC 2047 인코딩입니다. 디코딩은 EUC-KR, ISO-2022-JP 등 다른 문자셋도 처리합니다.',
    options: [{ id: 'enc', label: '방식', type: 'select', default: 'B', mode: 'encode', choices: [['B', 'B (Base64)'], ['Q', 'Q (Quoted-Printable)']] }],
    encode: (s, o) => mimeWordEncode(s, o),
    decode: (s) => mimeWordDecode(s),
  });
})(globalThis.DecryptLab);
