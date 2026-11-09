/* 고전 암호 › Polybius 사각형 */
(function (DL) {
  'use strict';
  const { keySquare, A25, prep25, ENC_DEC } = DL.kits.classic;

  function polybiusEnc(s, key) {
    const sq = keySquare(key, A25);
    return Array.from(prep25(s), (c) => { const i = sq.indexOf(c); return `${Math.floor(i / 5) + 1}${(i % 5) + 1}`; }).join(' ');
  }
  function polybiusDec(s, key) {
    const sq = keySquare(key, A25);
    const d = s.replace(/[^1-5]/g, '');
    if (!d) throw new Error('1–5 사이의 좌표 숫자가 없습니다.');
    if (d.length % 2) throw new Error('좌표 숫자의 개수가 홀수입니다.');
    return d.match(/../g).map((p) => sq[(p[0] - 1) * 5 + (p[1] - 1)]).join('');
  }

  DL.addTool('classic', {
    id: 'polybius', name: 'Polybius 사각형', short: '글자 → 행·열 숫자',
    desc: '5×5 격자에서 각 글자를 행과 열 번호(11–55)로 바꿉니다. 탭 코드, Nihilist 암호 등의 기반입니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키 (선택)', type: 'text', default: '' }],
    encode: (s, o) => polybiusEnc(s, o.key),
    decode: (s, o) => polybiusDec(s, o.key),
  });
})(globalThis.DecryptLab);
