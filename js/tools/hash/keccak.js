/* 해시·MAC·KDF › Keccak (원본 패딩) */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, keccakHash, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'keccak', name: 'Keccak', short: '이더리움 · SHA-3 이전 패딩',
    desc: 'SHA-3로 표준화되기 전의 원래 Keccak 패딩을 쓰는 해시입니다. 이더리움 주소·트랜잭션 해시(Keccak-256)에서 사용되며 SHA3-256과 값이 다릅니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      { id: 'size', label: '종류', type: 'select', default: '256', choices: [['256', 'Keccak-256'], ['512', 'Keccak-512']] },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(keccakHash(readBytes(s, o.inFmt), Number(o.size))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
