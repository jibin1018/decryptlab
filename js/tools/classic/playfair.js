/* 고전 암호 › Playfair 암호 */
(function (DL) {
  'use strict';
  const { mod, keySquare, A25, prep25, ENC_DEC } = DL.kits.classic;

  function playfairPairs(s) {
    const t = prep25(s);
    const pairs = [];
    for (let i = 0; i < t.length;) {
      const a = t[i];
      let b = t[i + 1];
      if (!b) { b = a === 'X' ? 'Q' : 'X'; i++; }
      else if (a === b) { b = a === 'X' ? 'Q' : 'X'; i++; }
      else i += 2;
      pairs.push(a + b);
    }
    return pairs;
  }
  function playfair(s, key, dir) {
    const sq = keySquare(key, A25);
    const pos = (c) => { const i = sq.indexOf(c); return [Math.floor(i / 5), i % 5]; };
    const pairs = dir > 0 ? playfairPairs(s) : (() => {
      const t = prep25(s);
      if (!t) throw new Error('영문자가 없습니다.');
      if (t.length % 2) throw new Error('Playfair 암호문은 글자 수가 짝수여야 합니다.');
      return t.match(/../g);
    })();
    return pairs.map(([a, b]) => {
      const [r1, c1] = pos(a), [r2, c2] = pos(b);
      if (r1 === r2) return sq[r1 * 5 + mod(c1 + dir, 5)] + sq[r2 * 5 + mod(c2 + dir, 5)];
      if (c1 === c2) return sq[mod(r1 + dir, 5) * 5 + c1] + sq[mod(r2 + dir, 5) * 5 + c2];
      return sq[r1 * 5 + c2] + sq[r2 * 5 + c1];
    }).join(' ');
  }

  DL.addTool('classic', {
    id: 'playfair', name: 'Playfair 암호', short: '5×5 행렬 · 두 글자 단위',
    desc: '키로 만든 5×5 표에서 두 글자씩 묶어 위치 규칙으로 치환합니다. J는 I로 합치고, 같은 글자가 연속되면 사이에 X를 넣습니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키', type: 'text', default: 'PLAYFAIR EXAMPLE' }],
    encode: (s, o) => playfair(s, o.key, 1),
    decode: (s, o) => playfair(s, o.key, -1),
  });
})(globalThis.DecryptLab);
