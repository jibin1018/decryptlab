/* 해시·MAC·KDF › Whirlpool */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, whirlpool, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'whirlpool', name: 'Whirlpool', short: '512비트 · ISO/IEC 10118-3',
    desc: 'AES와 유사한 구조의 512비트 해시(ISO/IEC 10118-3)입니다. TrueCrypt 등 일부 디스크 암호화 도구에서 사용되었습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(whirlpool(readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
