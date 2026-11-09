/* 해시·MAC·KDF › SHA-2 */
(function (DL) {
  'use strict';
  const { toHex, readBytes, fmtOption, sha, compareLine } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'sha2', name: 'SHA-2', short: 'SHA-256/384/512',
    desc: '현재 가장 널리 쓰이는 해시 계열입니다. TLS 인증서, 서명, 무결성 검증에 표준으로 사용됩니다. 출력 크기를 골라 계산하세요. (SHA-224는 브라우저 Web Crypto가 지원하지 않아 제외했습니다.)',
    fileInput: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      { id: 'size', label: '종류', type: 'select', default: 'SHA-256', choices: [['SHA-256', 'SHA-256'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']] },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: async (s, o) => { const v = toHex(await sha(o.size, readBytes(s, o.inFmt))); return v + compareLine(o.compare, v); },
  });
})(globalThis.DecryptLab);
