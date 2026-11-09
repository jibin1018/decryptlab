/* 대칭키 암호 › RC4 */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, rc4, ENC_DEC, keyOpt, keyFmt, ptFmt, ctFmt } = DL.kits.symmetric;

  DL.addTool('symmetric', {
    id: 'rc4', name: 'RC4', short: '레거시 스트림 암호 · drop-N',
    desc: '과거 WEP, SSL에서 쓰였던 스트림 암호입니다. 현재는 취약하지만 악성코드의 설정·통신 암호화에 여전히 자주 등장합니다. 암호화와 복호화가 같은 연산입니다.',
    modes: ENC_DEC,
    options: [
      keyOpt('Key'), { ...keyFmt('text') },
      { id: 'drop', label: '초기 키스트림 버림 (drop)', type: 'number', default: 0, min: 0 },
      ptFmt, { ...ctFmt, default: 'hex' },
    ],
    encrypt: (s, o) => formatBytes(rc4(readBytes(o.key, o.keyFmt), readBytes(s, o.ptFmt), Number(o.drop) || 0), o.ctFmt),
    decrypt: (s, o) => formatBytes(rc4(readBytes(o.key, o.keyFmt), readBytes(s.trim(), o.ctFmt), Number(o.drop) || 0), o.ptFmt),
  });
})(globalThis.DecryptLab);
