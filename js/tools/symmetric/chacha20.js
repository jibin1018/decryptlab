/* 대칭키 암호 › ChaCha20-Poly1305 */
(function (DL) {
  'use strict';
  const { utf8, readBytes, formatBytes, chacha20, chachaPoly, ENC_DEC, keyOpt, keyFmt, ivOpt, ivFmt, ptFmt, ctFmt } = DL.kits.symmetric;

  DL.addTool('symmetric', {
    id: 'chacha20', name: 'ChaCha20-Poly1305', short: 'RFC 8439 인증 암호',
    desc: 'TLS 1.3, WireGuard 등에서 쓰는 현대적 스트림 암호 기반 인증 암호입니다. 키 32 B, nonce 12 B를 사용하며 암호문 끝에 16 B 태그가 붙습니다. "Poly1305 없이"를 선택하면 순수 ChaCha20 스트림 암호로 동작합니다.',
    slow: true, modes: ENC_DEC,
    options: [
      { id: 'variant', label: '방식', type: 'select', default: 'aead', choices: [['aead', 'ChaCha20-Poly1305'], ['raw', 'ChaCha20 (Poly1305 없이)']] },
      keyOpt('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), keyFmt(),
      ivOpt('000000000000004a00000000', 'Nonce'), { ...ivFmt, label: 'Nonce 형식' },
      { id: 'counter', label: '초기 카운터', type: 'number', default: 1, min: 0, when: (o) => o.variant === 'raw' },
      { id: 'aad', label: 'AAD', type: 'text', default: '', when: (o) => o.variant === 'aead' },
      ptFmt, ctFmt,
    ],
    encrypt: (s, o) => {
      const key = readBytes(o.key, o.keyFmt), nonce = readBytes(o.iv, o.ivFmt), data = readBytes(s, o.ptFmt);
      const out = o.variant === 'raw' ? chacha20(key, nonce, Number(o.counter) || 0, data) : (chacha20(key, nonce, 0, new Uint8Array(0)), chachaPoly(key, nonce, data, utf8(o.aad || ''), false));
      return formatBytes(out, o.ctFmt);
    },
    decrypt: (s, o) => {
      const key = readBytes(o.key, o.keyFmt), nonce = readBytes(o.iv, o.ivFmt), data = readBytes(s.trim(), o.ctFmt);
      if (o.variant !== 'raw') chacha20(key, nonce, 0, new Uint8Array(0)); // 키/nonce 길이 검증
      const out = o.variant === 'raw' ? chacha20(key, nonce, Number(o.counter) || 0, data) : chachaPoly(key, nonce, data, utf8(o.aad || ''), true);
      return formatBytes(out, o.ptFmt);
    },
  });
})(globalThis.DecryptLab);
