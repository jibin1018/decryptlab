/* 고전 암호 › Hill 암호 */
(function (DL) {
  'use strict';
  const { A, mod, lettersOnly, modInv, ENC_DEC } = DL.kits.classic;

  function hillMatrix(key) {
    const t = key.trim();
    let nums;
    if (/^[\d\s,;-]+$/.test(t)) nums = t.split(/[\s,;]+/).filter(Boolean).map(Number);
    else nums = Array.from(lettersOnly(t), (c) => c.charCodeAt(0) - 65);
    const n = Math.round(Math.sqrt(nums.length));
    if (n < 2 || n * n !== nums.length) throw new Error('키는 4개(2×2) 또는 9개(3×3) 숫자, 혹은 4/9글자 영단어여야 합니다.');
    return { n, m: Array.from({ length: n }, (_, r) => nums.slice(r * n, r * n + n).map((v) => mod(v, 26))) };
  }
  function det(m) {
    if (m.length === 2) return m[0][0] * m[1][1] - m[0][1] * m[1][0];
    return m[0].reduce((acc, v, c) => acc + (c % 2 ? -1 : 1) * v * det(m.slice(1).map((row) => row.filter((_, j) => j !== c))), 0);
  }
  function invMatrix(m) {
    const n = m.length;
    const d = mod(det(m), 26);
    const dInv = modInv(d, 26);
    if (dInv === null) throw new Error(`키 행렬의 행렬식(${d})이 26과 서로소가 아니라 역행렬이 없습니다. 다른 키를 사용하세요.`);
    if (n === 2) return [[m[1][1], -m[0][1]], [-m[1][0], m[0][0]]].map((r) => r.map((v) => mod(v * dInv, 26)));
    const adj = Array.from({ length: n }, () => Array(n).fill(0));
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
      const minor = m.filter((_, i) => i !== r).map((row) => row.filter((_, j) => j !== c));
      adj[c][r] = ((r + c) % 2 ? -1 : 1) * det(minor);
    }
    return adj.map((row) => row.map((v) => mod(v * dInv, 26)));
  }
  function hill(s, key, dir) {
    const { n, m } = hillMatrix(key);
    const mat = dir > 0 ? m : invMatrix(m);
    if (dir > 0) invMatrix(m); // 복호화 불가능한 키는 미리 경고
    const t = lettersOnly(s);
    const padded = t + 'X'.repeat((n - (t.length % n)) % n);
    let out = '';
    for (let i = 0; i < padded.length; i += n) {
      const v = Array.from(padded.slice(i, i + n), (c) => c.charCodeAt(0) - 65);
      for (let r = 0; r < n; r++) out += A[mod(mat[r].reduce((acc, x, c) => acc + x * v[c], 0), 26)];
    }
    return out;
  }

  DL.addTool('classic', {
    id: 'hill', name: 'Hill 암호', short: '2×2 / 3×3 행렬 곱',
    desc: '글자를 벡터로 보고 키 행렬을 곱하는 선형대수 기반 암호입니다. 키는 숫자 4/9개 또는 4/9글자 영단어(예: GYBNQKURP)로 입력합니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키 행렬', type: 'text', default: 'GYBNQKURP' }],
    encode: (s, o) => hill(s, o.key, 1),
    decode: (s, o) => hill(s, o.key, -1),
  });
})(globalThis.DecryptLab);
