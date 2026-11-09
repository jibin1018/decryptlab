/* 고전 암호 › 레일펜스 암호 */
(function (DL) {
  'use strict';
  const { ENC_DEC } = DL.kits.classic;

  function railEncode(s, rails) {
    const chars = Array.from(s);
    if (rails < 2) return s;
    const rows = Array.from({ length: rails }, () => []);
    let r = 0, d = 1;
    for (const c of chars) {
      rows[r].push(c);
      if (r === 0) d = 1; else if (r === rails - 1) d = -1;
      r += d;
    }
    return rows.flat().join('');
  }
  function railDecode(s, rails) {
    const chars = Array.from(s);
    if (rails < 2) return s;
    const pattern = [];
    let r = 0, d = 1;
    for (let i = 0; i < chars.length; i++) {
      pattern.push(r);
      if (r === 0) d = 1; else if (r === rails - 1) d = -1;
      r += d;
    }
    const counts = Array(rails).fill(0);
    pattern.forEach((p) => counts[p]++);
    const rows = []; let pos = 0;
    for (let i = 0; i < rails; i++) { rows.push(chars.slice(pos, pos + counts[i])); pos += counts[i]; }
    const idx = Array(rails).fill(0);
    return pattern.map((p) => rows[p][idx[p]++]).join('');
  }

  DL.addTool('classic', {
    id: 'railfence', name: '레일펜스 암호', short: '지그재그 전치',
    desc: '글자를 여러 줄에 지그재그로 적은 뒤 줄 순서대로 읽는 전치 암호입니다.',
    modes: ENC_DEC,
    options: [{ id: 'rails', label: '레일 수', type: 'number', default: 3, min: 2, max: 50 }],
    encode: (s, o) => railEncode(s, Math.max(2, Number(o.rails) || 2)),
    decode: (s, o) => railDecode(s, Math.max(2, Number(o.rails) || 2)),
  });
})(globalThis.DecryptLab);
