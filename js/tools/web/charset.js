/* 웹·문자 인코딩 › 문자셋 해석 */
(function (DL) {
  'use strict';
  const { readBytes, fmtOption } = DL.kits.web;

  const CHARSETS = [
    ['utf-8', 'UTF-8'], ['euc-kr', 'EUC-KR / CP949'], ['shift_jis', 'Shift_JIS'], ['euc-jp', 'EUC-JP'],
    ['gb18030', 'GB18030 / GBK'], ['big5', 'Big5'], ['windows-1252', 'Windows-1252'], ['iso-8859-1', 'ISO-8859-1'],
    ['koi8-r', 'KOI8-R'], ['windows-1251', 'Windows-1251'], ['utf-16le', 'UTF-16LE'], ['utf-16be', 'UTF-16BE'],
  ];
  function charsetDecode(bytes, cs) {
    const run = (c) => new TextDecoder(c).decode(bytes);
    if (cs !== 'all') return run(cs);
    return CHARSETS.map(([c, label]) => {
      let t;
      try { t = run(c); } catch { t = '(지원하지 않음)'; }
      const bad = (t.match(/�/g) || []).length;
      return `■ ${label}${bad ? `  — 깨진 문자 ${bad}개` : ''}\n${t}`;
    }).join('\n\n');
  }
  DL.fn.charsetDecode = charsetDecode;

  DL.addTool('web', {
    id: 'charset', name: '문자셋 해석', short: 'EUC-KR · Shift_JIS 등 깨진 글자 복원',
    desc: '바이트를 여러 문자셋으로 해석해 봅니다. "怨좉컼" 같이 깨진 한글은 EUC-KR 바이트를 다른 문자셋으로 읽은 경우가 많습니다.',
    modes: [{ id: 'decode', label: '해석', inLabel: '바이트', placeholder: '16진수 바이트 (예: c7 d1 b1 db)' }],
    fileInput: true,
    options: [
      fmtOption('fmt', '입력 형식', 'hex', ['hex', 'base64']),
      { id: 'cs', label: '문자셋', type: 'select', default: 'all', choices: [['all', '모두 비교'], ...CHARSETS] },
    ],
    decode: (s, o) => charsetDecode(readBytes(s, o.fmt), o.cs),
  });
})(globalThis.DecryptLab);
