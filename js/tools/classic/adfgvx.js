/* 고전 암호 › ADFGVX 암호 */
(function (DL) {
  'use strict';
  const { A25, A36, prep25, keySquare, columnarEnc, columnarDec, ENC_DEC } = DL.kits.classic;

  function adfgvx(s, squareKey, transKey, dir, variant) {
    const labels = variant === 'adfgx' ? 'ADFGX' : 'ADFGVX';
    const size = labels.length;
    const sq = keySquare(squareKey, size === 5 ? A25 : A36);
    if (dir > 0) {
      const t = size === 5 ? prep25(s) : s.toUpperCase().replace(/[^A-Z0-9]/g, '');
      const mid = Array.from(t, (c) => { const i = sq.indexOf(c); return labels[Math.floor(i / size)] + labels[i % size]; }).join('');
      return columnarEnc(mid, transKey);
    }
    const t = s.toUpperCase().replace(new RegExp(`[^${labels}]`, 'g'), '');
    if (!t) throw new Error(`${labels} 문자가 없습니다.`);
    const mid = columnarDec(t, transKey);
    if (mid.length % 2) throw new Error('전치를 푼 결과의 길이가 홀수입니다. 키를 확인하세요.');
    return mid.match(/../g).map((p) => sq[labels.indexOf(p[0]) * size + labels.indexOf(p[1])]).join('');
  }

  DL.addTool('classic', {
    id: 'adfgvx', name: 'ADFGVX 암호', short: '1차 대전 독일군 암호',
    desc: '6×6 격자로 글자를 ADFGVX 두 글자로 바꾼 뒤, 두 번째 키로 열 전치합니다. ADFGX(5×5) 변형도 지원합니다.',
    modes: ENC_DEC,
    options: [
      { id: 'variant', label: '종류', type: 'select', default: 'adfgvx', choices: [['adfgvx', 'ADFGVX (6×6)'], ['adfgx', 'ADFGX (5×5)']] },
      { id: 'square', label: '격자 키', type: 'text', default: 'PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8' },
      { id: 'trans', label: '전치 키', type: 'text', default: 'PRIVACY' },
    ],
    encode: (s, o) => adfgvx(s, o.square, o.trans, 1, o.variant),
    decode: (s, o) => adfgvx(s, o.square, o.trans, -1, o.variant),
  });
})(globalThis.DecryptLab);
