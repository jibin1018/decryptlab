/* 공개키 암호·서명 › RSA-OAEP */
(function (DL) {
  'use strict';
  const { utf8, readBytes, formatBytes, fmtOption, subtle, importKey, exportPair, webcryptoError, KEYGEN, pemOpt } = DL.kits.asymmetric;

  DL.addTool('asymmetric', {
    id: 'rsa', name: 'RSA-OAEP', short: '공개키 암호화 · 개인키 복호화',
    desc: '공개키로 암호화하고 개인키로 복호화합니다. OAEP는 현재 권장되는 RSA 패딩입니다. PEM(PKCS#8·PKCS#1·SPKI), 인증서, JWK를 모두 받습니다.',
    slow: true,
    modes: [
      { id: 'encrypt', label: '암호화', inLabel: '평문', outLabel: '암호문' },
      { id: 'decrypt', label: '복호화', inLabel: '암호문', outLabel: '평문' },
      KEYGEN,
    ],
    options: [
      { id: 'hash', label: 'OAEP 해시', type: 'select', default: 'SHA-256', choices: [['SHA-256', 'SHA-256'], ['SHA-1', 'SHA-1'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']] },
      { id: 'bits', label: '키 길이', type: 'select', default: '2048', mode: 'keygen', choices: [['2048', '2048비트'], ['3072', '3072비트'], ['4096', '4096비트']] },
      { ...pemOpt('pub', '공개키'), mode: 'encrypt' },
      { ...pemOpt('priv', '개인키'), mode: 'decrypt' },
      { ...fmtOption('ctFmt', '암호문 형식', 'base64', ['base64', 'hex']), mode: ['encrypt', 'decrypt'] },
    ],
    keygen: async (_, o) => {
      try {
        return await exportPair(await subtle().generateKey({ name: 'RSA-OAEP', modulusLength: Number(o.bits), publicExponent: Uint8Array.of(1, 0, 1), hash: o.hash }, true, ['encrypt', 'decrypt']));
      } catch (e) { throw webcryptoError(e); }
    },
    encrypt: async (s, o) => {
      const key = await importKey(o.pub, { name: 'RSA-OAEP', hash: o.hash }, ['encrypt'], 'public');
      try { return formatBytes(new Uint8Array(await subtle().encrypt({ name: 'RSA-OAEP' }, key, utf8(s))), o.ctFmt); }
      catch { throw new Error('암호화 실패 — 평문이 키 길이에 비해 너무 깁니다. (2048비트·SHA-256 기준 최대 190 B)'); }
    },
    decrypt: async (s, o) => {
      const key = await importKey(o.priv, { name: 'RSA-OAEP', hash: o.hash }, ['decrypt'], 'private');
      try { return formatBytes(new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, key, readBytes(s.trim(), o.ctFmt))), 'text'); }
      catch (e) { if (/UTF-8/.test(e.message)) throw e; throw new Error('복호화 실패 — 키가 맞지 않거나, OAEP 해시 설정이 다르거나, 암호문이 손상되었습니다.'); }
    },
  });
})(globalThis.DecryptLab);
