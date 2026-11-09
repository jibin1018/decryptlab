/* 해시·MAC·KDF › SHA-1 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, sha, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'sha1', name: 'SHA-1', short: '160비트 · 레거시 (충돌 취약)',
    desc: '160비트 해시입니다. 충돌 공격(SHAttered)이 입증되어 서명 등 보안 용도로는 권장되지 않지만, Git 객체 ID나 오래된 프로토콜에서 볼 수 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: async (s, o) => { const v = toHex(await sha('SHA-1', readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
