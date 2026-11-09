/* 고전 암호 › Bifid 암호 */
(function (DL) {
  'use strict';
  const { keySquare, A25, prep25, ENC_DEC } = DL.kits.classic;

  function bifid(s, key, dir, period) {
    const sq = keySquare(key, A25);
    const t = prep25(s);
    const p = Number(period) > 0 ? Number(period) : t.length;
    let out = '';
    for (let start = 0; start < t.length; start += p) {
      const block = t.slice(start, start + p);
      const coords = Array.from(block, (c) => { const i = sq.indexOf(c); return [Math.floor(i / 5), i % 5]; });
      if (dir > 0) {
        const line = [...coords.map((c) => c[0]), ...coords.map((c) => c[1])];
        for (let i = 0; i < line.length; i += 2) out += sq[line[i] * 5 + line[i + 1]];
      } else {
        const line = coords.flat();
        const n = block.length;
        for (let i = 0; i < n; i++) out += sq[line[i] * 5 + line[n + i]];
      }
    }
    return out;
  }

  DL.addTool('classic', {
    id: 'bifid', name: 'Bifid 암호', short: 'Polybius + 좌표 섞기',
    desc: '글자의 행 좌표와 열 좌표를 따로 모아 이어 붙인 뒤 다시 짝지어 치환과 전치를 동시에 수행합니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키', type: 'text', default: 'BGWKZQPNDSIOAXEFCLUMTHYVR' }, { id: 'period', label: '주기 (0=전체)', type: 'number', default: 0, min: 0, max: 100 }],
    encode: (s, o) => bifid(s, o.key, 1, o.period),
    decode: (s, o) => bifid(s, o.key, -1, o.period),
  });
})(globalThis.DecryptLab);
