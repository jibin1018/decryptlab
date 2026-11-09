/* 해시·MAC·KDF › HMAC */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, hmac, compareLine, HASHES } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'hmac', name: 'HMAC', short: '키가 있는 메시지 인증 코드',
    desc: '비밀키와 해시를 결합해 메시지가 변조되지 않았고 키를 가진 쪽이 만들었음을 증명합니다. API 요청 서명, 웹훅 검증, JWT HS256 등에 쓰입니다.',
    fileInput: true,
    modes: [{ id: 'run', label: 'HMAC 계산', inLabel: '메시지', outLabel: 'HMAC' }],
    options: [
      { id: 'algo', label: '해시', type: 'select', default: 'SHA-256', choices: [...HASHES, ['MD5', 'MD5']] },
      { id: 'key', label: '키', type: 'text', default: 'secret', wide: true },
      fmtOption('keyFmt', '키 형식', 'text'),
      fmtOption('inFmt', '메시지 형식', 'text'),
      fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: async (s, o) => {
      const v = formatBytes(await hmac(o.algo, readBytes(o.key, o.keyFmt), readBytes(s, o.inFmt)), o.outFmt);
      return v + compareLine(o.compare, v);
    },
  });
})(globalThis.DecryptLab);
