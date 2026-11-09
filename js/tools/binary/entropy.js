/* 바이너리 분석 › 엔트로피 분석 */
(function (DL) {
  'use strict';
  const { readBytes, entropy, asciiChar, IN } = DL.kits.binary;

  const BARS = '▁▂▃▄▅▆▇█';
  function entropyReport(bytes) {
    if (!bytes.length) throw new Error('분석할 데이터가 없습니다.');
    const h = entropy(bytes);
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const unique = freq.filter(Boolean).length;
    const printable = bytes.filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13).length / bytes.length;
    const nulls = freq[0] / bytes.length;
    const expected = bytes.length / 256;
    const chi = freq.reduce((a, f) => a + ((f - expected) ** 2) / expected, 0);
    let verdict;
    if (printable > 0.95) verdict = h > 5.6 ? 'Base64/Hex 같은 인코딩된 텍스트일 가능성이 높습니다.' : '일반 텍스트로 보입니다.';
    else if (h > 7.9) verdict = '매우 무작위적입니다 — 암호화되었거나 압축된 데이터일 가능성이 높습니다.';
    else if (h > 7.2) verdict = '무작위성이 높습니다 — 압축 데이터, 암호문, 또는 미디어 파일일 수 있습니다.';
    else if (h > 5) verdict = '구조가 있는 바이너리(실행 파일, 데이터 파일 등)로 보입니다.';
    else verdict = '반복이 많은 데이터입니다 — 텍스트, 패딩, 또는 단순 XOR 데이터일 수 있습니다.';

    const lines = [
      `크기             ${bytes.length.toLocaleString()} B`,
      `엔트로피         ${h.toFixed(4)} 비트/바이트  (최대 8)`,
      `서로 다른 바이트 ${unique} / 256`,
      `출력 가능 문자   ${(printable * 100).toFixed(1)}%`,
      `0x00 비율        ${(nulls * 100).toFixed(1)}%`,
      `카이제곱(균등)   ${chi.toFixed(1)}  ${bytes.length >= 2560 ? (chi < 330 ? '(균등 분포에 가까움 — 암호문 특징)' : '(균등하지 않음)') : '(데이터가 적어 판단 어려움)'}`,
      '', `판단: ${verdict}`,
    ];
    if (bytes.length >= 512) {
      const blocks = Math.min(64, Math.floor(bytes.length / 64));
      const size = Math.ceil(bytes.length / blocks);
      const hs = [];
      for (let i = 0; i < bytes.length; i += size) hs.push(entropy(bytes.subarray(i, i + size)));
      lines.push('', `■ 구간별 엔트로피 (${size.toLocaleString()} B 단위, 0–8)`, '  ' + hs.map((v) => BARS[Math.min(7, Math.floor(v))]).join(''));
      lines.push('  구간 사이 엔트로피 차이가 크면 암호화·압축된 영역이 섞여 있다는 뜻입니다.');
    }
    const top = freq.map((f, b) => [b, f]).sort((a, b) => b[1] - a[1]).slice(0, 8);
    lines.push('', '■ 가장 많은 바이트');
    for (const [b, f] of top) if (f) lines.push(`  0x${b.toString(16).padStart(2, '0')} ${asciiChar(b) === '.' ? ' ' : `'${asciiChar(b)}'`}  ${((f / bytes.length) * 100).toFixed(2)}%`);
    return lines.join('\n');
  }
  DL.fn.entropyReport = entropyReport;

  DL.addTool('binary', {
    id: 'entropy', name: '엔트로피 분석', short: '암호화·압축 여부 추정',
    desc: '바이트 분포의 무작위성(섀넌 엔트로피)을 측정합니다. 8에 가까우면 암호문이나 압축 데이터, 낮으면 텍스트나 단순 인코딩일 가능성이 높습니다. 구간별 그래프로 파일 안의 암호화 영역도 찾을 수 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '분석', inLabel: '데이터', outLabel: '분석 결과' }],
    options: [IN('text')],
    run: (s, o) => entropyReport(readBytes(s, o.inFmt)),
  });
})(globalThis.DecryptLab);
