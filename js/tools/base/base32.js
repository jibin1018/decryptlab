/* Base 계열 › Base32 (RFC 4648) */
(function (DL) {
  'use strict';
  const { readBytes, IN } = DL.kits.base;

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32encode(bytes, { nopad = false } = {}) {
    let out = '', val = 0, bits = 0;
    for (const b of bytes) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
      val &= (1 << bits) - 1;
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    if (!nopad) while (out.length % 8) out += '=';
    return out;
  }
  function b32decode(s) {
    const clean = s.replace(/[\s=]/g, '').toUpperCase();
    const out = []; let val = 0, bits = 0;
    for (const c of clean) {
      const i = B32.indexOf(c);
      if (i < 0) throw new Error(`Base32 문자가 아닙니다: "${c}"`);
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; }
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { b32encode, b32decode });

  DL.addTool('base', {
    id: 'base32', name: 'Base32', short: 'RFC 4648 · OTP 시크릿',
    desc: 'A–Z와 2–7만 사용하는 인코딩입니다. 대소문자 구분이 없어 OTP 시크릿 키 등에 자주 쓰입니다.',
    options: [IN, { id: 'nopad', label: '패딩(=) 제거', type: 'checkbox', default: false, mode: 'encode' }],
    encode: (s, o) => b32encode(readBytes(s, o.inFmt), o),
    decode: (s) => b32decode(s),
  });
})(globalThis.DecryptLab);
