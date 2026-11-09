/* 고전 암호 › 빈도 분석 · 키 추정 */
(function (DL) {
  'use strict';
  const { A, mod, lettersOnly, caesar, vigenere, counts, ioc, chi2, bestShift } = DL.kits.classic;

  function analyzeClassic(s) {
    const t = lettersOnly(s);
    if (t.length < 20) throw new Error('신뢰할 수 있는 분석에는 영문자가 최소 20자 이상 필요합니다.');
    const c = counts(t);
    const ic = ioc(t);
    const lines = [];
    lines.push(`영문자 ${t.length}자 · 일치 지수(IC) ${ic.toFixed(4)}`);
    lines.push(`  영어 평문/단일 치환 ≈ 0.066, 무작위/다중 치환 ≈ 0.038`);
    lines.push(ic > 0.058 ? '  → 단일 치환(카이사르·Atbash·Affine·치환 암호) 또는 전치 암호일 가능성이 높습니다.'
      : ic < 0.047 ? '  → 비즈네르 같은 다중 치환 암호일 가능성이 높습니다.' : '  → 판단이 애매합니다. 텍스트가 더 길면 정확해집니다.');
    lines.push('', '■ 문자 빈도 (상위 10)');
    const top = c.map((f, i) => [A[i], f]).sort((a, b) => b[1] - a[1]).slice(0, 10);
    for (const [ch, f] of top) {
      const p = (f / t.length) * 100;
      lines.push(`  ${ch}  ${'█'.repeat(Math.round(p / 1.5)).padEnd(10)} ${p.toFixed(1)}%`);
    }
    const cs = bestShift(t);
    lines.push('', `■ 카이사르로 가정했을 때 최적 시프트: ${cs.shift} (χ² ${cs.score.toFixed(1)})`);
    lines.push(`  ${caesar(s, -cs.shift).slice(0, 200)}`);

    // 비즈네르 키 길이 추정 (열별 평균 IC)
    const cands = [];
    for (let L = 1; L <= Math.min(20, Math.floor(t.length / 4)); L++) {
      let sum = 0;
      for (let k = 0; k < L; k++) sum += ioc(t.split('').filter((_, i) => i % L === k).join(''));
      cands.push({ L, ic: sum / L });
    }
    // 긴 키는 짧은 키의 배수에서도 높은 IC가 나오므로, 0.06에 가까운 가장 짧은 길이를 우선한다
    const good = cands.filter((x) => x.ic > 0.055);
    const ranked = good.length ? good.sort((a, b) => a.L - b.L) : cands.slice().sort((a, b) => b.ic - a.ic);
    lines.push('', '■ 비즈네르로 가정한 키 길이 후보 (열별 평균 IC)');
    lines.push('  ' + cands.slice().sort((a, b) => b.ic - a.ic).slice(0, 5).map((x) => `${x.L}글자: ${x.ic.toFixed(4)}`).join('  ·  '));
    for (const { L } of ranked.slice(0, 2)) {
      if (L === 1) continue;
      let key = '';
      for (let k = 0; k < L; k++) key += A[bestShift(t.split('').filter((_, i) => i % L === k).join('')).shift];
      lines.push('', `  키 길이 ${L} → 추정 키 "${key}"`);
      lines.push(`  ${vigenere(s, key, -1).slice(0, 300)}`);
    }
    lines.push('', '※ 통계적 추정이므로 짧은 텍스트나 영어가 아닌 평문에서는 틀릴 수 있습니다.');
    return lines.join('\n');
  }

  DL.addTool('classic', {
    id: 'analyze', name: '빈도 분석 · 키 추정', short: 'IC · χ² · 비즈네르 키 길이',
    desc: '암호문의 문자 빈도와 일치 지수(IC)로 단일/다중 치환 여부를 판별하고, 카이사르 시프트와 비즈네르 키를 통계적으로 추정합니다.',
    modes: [{ id: 'run', label: '분석', inLabel: '암호문', placeholder: '영문 암호문 (길수록 정확합니다)' }],
    run: (s) => analyzeClassic(s),
  });
})(globalThis.DecryptLab);
