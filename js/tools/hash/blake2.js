/* 해시·MAC·KDF › BLAKE2 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, blake2b, blake2s, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'blake2', name: 'BLAKE2', short: 'BLAKE2b · BLAKE2s',
    desc: 'MD5·SHA보다 빠르면서 SHA-3 수준의 안전성을 갖는 해시입니다. BLAKE2b는 64비트 플랫폼(최대 512비트), BLAKE2s는 32비트 플랫폼에 최적화돼 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      { id: 'variant', label: '종류', type: 'select', default: '2b-512', choices: [['2b-512', 'BLAKE2b-512'], ['2b-256', 'BLAKE2b-256'], ['2s-256', 'BLAKE2s-256']] },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => {
      const b = readBytes(s, o.inFmt);
      const v = toHex(o.variant === '2s-256' ? blake2s(b, 32) : blake2b(b, o.variant === '2b-256' ? 32 : 64));
      return v + compareLine(o.compare, v);
    },
  });
})(globalThis.DecryptLab);
