/* 해시·MAC·KDF › SHA-3 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, sha3, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'sha3', name: 'SHA-3', short: 'FIPS 202 · 224/256/384/512',
    desc: 'Keccak 기반의 SHA-3(FIPS 202) 해시입니다. SHA-2와 내부 구조가 완전히 달라 설계상 안전 여유가 다릅니다. 표준 패딩을 사용합니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      { id: 'size', label: '종류', type: 'select', default: '256', choices: [['224', 'SHA3-224'], ['256', 'SHA3-256'], ['384', 'SHA3-384'], ['512', 'SHA3-512']] },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(sha3(readBytes(s, o.inFmt), Number(o.size))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
