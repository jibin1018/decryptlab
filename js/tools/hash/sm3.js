/* 해시·MAC·KDF › SM3 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, sm3, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'sm3', name: 'SM3', short: '256비트 · 중국 국가 표준',
    desc: '중국 국가암호관리국이 정한 256비트 해시(GM/T 0004)입니다. SM2 서명·SM4 암호와 함께 중국 상용 암호 체계에서 사용됩니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(sm3(readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
