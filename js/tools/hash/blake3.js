/* 해시·MAC·KDF › BLAKE3 (256비트) */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, blake3, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'blake3', name: 'BLAKE3', short: '256비트 · 초고속 트리 해시',
    desc: '병렬화된 트리 구조로 매우 빠른 최신 해시입니다. 여기서는 기본 256비트 출력을 냅니다. 원하는 길이로 뽑으려면 "가변 길이 해시(XOF)"에서 BLAKE3를 고르세요.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(blake3(readBytes(s, o.inFmt), 32)); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
