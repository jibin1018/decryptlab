/* 해시·MAC·KDF › RIPEMD-160 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, ripemd160, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'ripemd160', name: 'RIPEMD-160', short: '160비트 · 비트코인 주소',
    desc: '160비트 해시로, 비트코인 주소 생성(SHA-256 뒤 RIPEMD-160)에 쓰입니다. SHA-1과 길이는 같지만 설계가 다릅니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(ripemd160(readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
