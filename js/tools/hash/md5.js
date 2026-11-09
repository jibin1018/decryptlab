/* 해시·MAC·KDF › MD5 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, md5, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'md5', name: 'MD5', short: '128비트 · 레거시 (충돌 취약)',
    desc: '128비트 해시입니다. 충돌 공격이 알려져 보안 용도로는 쓰면 안 되지만, 파일 체크섬이나 레거시 시스템 호환에 여전히 등장합니다. 해시는 단방향이라 복호화할 수 없습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: (s, o) => { const v = toHex(md5(readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
