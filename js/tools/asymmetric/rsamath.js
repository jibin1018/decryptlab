/* 공개키 암호·서명 › 교과서 RSA (CTF) */
(function (DL) {
  'use strict';
  const { utf8, bigFromBytes, bigToBytes } = DL.kits.asymmetric;

  const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  function modInv(a, m) {
    let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error('e와 φ(n)이 서로소가 아니라 d를 계산할 수 없습니다.');
    return ((s0 % m) + m) % m;
  }
  function iroot(n, k) {
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / Number(k)) + 1);
    for (;;) { const y = ((k - 1n) * x + n / x ** (k - 1n)) / k; if (y >= x) return x; x = y; }
  }
  const parseInt_ = (s, name) => {
    const t = String(s || '').trim().replace(/[\s_]/g, '');
    if (!t) return null;
    try { return BigInt(t); } catch { throw new Error(`${name} 값을 정수로 해석할 수 없습니다 (10진수 또는 0x16진수).`); }
  };
  function fermat(n, limit = 200000) {
    let a = iroot(n, 2n);
    if (a * a < n) a++;
    for (let i = 0; i < limit; i++, a++) {
      const b2 = a * a - n, b = iroot(b2, 2n);
      if (b * b === b2) return [a - b, a + b];
    }
    return null;
  }
  function trialDivide(n, limit = 100000) {
    if (n % 2n === 0n) return [2n, n / 2n];
    for (let p = 3n; p < BigInt(limit); p += 2n) if (n % p === 0n) return [p, n / p];
    return null;
  }
  const bigToText = (m) => {
    const b = bigToBytes(m);
    try { const t = DL.utf8Decode(b, true); if (DL.printableScore(t) > 0.9) return t; } catch { /* 바이너리 */ }
    return null;
  };
  function report(m, log) {
    const text = bigToText(m);
    return [...log, '', `m (10진수)  ${m}`, `m (16진수)  0x${m.toString(16)}`, `m (텍스트)  ${text ?? '(읽을 수 있는 텍스트가 아님)'}`].join('\n');
  }
  function rsaSolve(cStr, o) {
    const c = parseInt_(cStr, '암호문 c');
    if (c === null) throw new Error('암호문 c를 입력하세요.');
    let n = parseInt_(o.n, 'n'), e = parseInt_(o.e, 'e') ?? 65537n, d = parseInt_(o.d, 'd');
    let p = parseInt_(o.p, 'p'), q = parseInt_(o.q, 'q');
    const log = [];
    if (p && q && !n) n = p * q;
    if (p && !q && n) q = n / p;
    if (!n) throw new Error('n(또는 p와 q)을 입력하세요.');
    if (!d && !(p && q)) {
      // 작은 e: m^e < n 이면 정수 e제곱근으로 바로 복원
      const m0 = iroot(c, e);
      if (m0 ** e === c) {
        log.push(`작은 지수 공격: m^${e} < n 이므로 c의 ${e}제곱근이 곧 평문입니다.`);
        return report(m0, log);
      }
      const f = trialDivide(n) || fermat(n);
      if (f) { [p, q] = f; log.push(`인수분해 성공 (${f[0] < 100000n ? '작은 소인수' : '페르마 — p와 q가 가까움'}): p = ${p}`); }
      else throw new Error('d나 p·q 없이 풀 수 없습니다. 작은 지수·작은 소인수·가까운 소수 공격이 모두 실패했습니다. (factordb.com 등에서 n의 인수분해를 확인해 보세요)');
    }
    if (!d) {
      const phi = (p - 1n) * (q - 1n);
      d = modInv(e, phi);
      log.push(`φ(n) = (p−1)(q−1), d = e⁻¹ mod φ(n) = ${d}`);
    }
    return report(modPow(c, d, n), log);
  }
  Object.assign(DL.fn, { modPow, modInv, iroot, rsaSolve });

  DL.addTool('asymmetric', {
    id: 'rsamath', name: '교과서 RSA (CTF)', short: 'n·e·c로 평문 복원 · 약점 공격',
    desc: '숫자로 주어진 RSA 문제를 풉니다. p·q나 d를 알면 바로 복호화하고, n과 e만 있으면 작은 지수(m^e < n), 작은 소인수, 가까운 소수(페르마) 공격을 차례로 시도합니다.',
    slow: true,
    modes: [
      { id: 'decrypt', label: '복호화', inLabel: '암호문 c', placeholder: '정수 (10진수 또는 0x16진수)' },
      { id: 'encrypt', label: '암호화', inLabel: '평문', outLabel: '암호문 c' },
    ],
    options: [
      { id: 'n', label: 'n', type: 'text', default: '', wide: true },
      { id: 'e', label: 'e', type: 'text', default: '65537' },
      { id: 'd', label: 'd (선택)', type: 'text', default: '', wide: true, mode: 'decrypt' },
      { id: 'p', label: 'p (선택)', type: 'text', default: '', mode: 'decrypt' },
      { id: 'q', label: 'q (선택)', type: 'text', default: '', mode: 'decrypt' },
    ],
    decrypt: (s, o) => rsaSolve(s, o),
    encrypt: (s, o) => {
      const n = parseInt_(o.n, 'n'), e = parseInt_(o.e, 'e') ?? 65537n;
      if (!n) throw new Error('n을 입력하세요.');
      const m = bigFromBytes(utf8(s));
      if (m >= n) throw new Error('평문이 n보다 큽니다. 더 짧은 평문이나 큰 n을 사용하세요.');
      const c = modPow(m, e, n);
      return `c (10진수)  ${c}\nc (16진수)  0x${c.toString(16)}`;
    },
  });
})(globalThis.DecryptLab);
