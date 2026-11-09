/* Base 계열 › Z85 (ZeroMQ Base85) */
(function (DL) {
  'use strict';
  const { readBytes, IN } = DL.kits.base;

  const Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  function z85encode(bytes) {
    if (bytes.length % 4) throw new Error(`Z85는 4바이트 배수만 인코딩할 수 있습니다. (현재 ${bytes.length}바이트)`);
    let out = '';
    for (let i = 0; i < bytes.length; i += 4) {
      let v = ((bytes[i] << 24) >>> 0) + (bytes[i + 1] << 16) + (bytes[i + 2] << 8) + bytes[i + 3];
      const enc = [];
      for (let j = 0; j < 5; j++) { enc.unshift(Z85[v % 85]); v = Math.floor(v / 85); }
      out += enc.join('');
    }
    return out;
  }
  function z85decode(s) {
    const clean = s.replace(/\s/g, '');
    if (clean.length % 5) throw new Error('Z85 문자열 길이는 5의 배수여야 합니다.');
    const out = [];
    for (let i = 0; i < clean.length; i += 5) {
      let v = 0;
      for (let j = 0; j < 5; j++) {
        const d = Z85.indexOf(clean[i + j]);
        if (d < 0) throw new Error(`Z85 문자가 아닙니다: "${clean[i + j]}"`);
        v = v * 85 + d;
      }
      if (v > 0xffffffff) throw new Error('Z85 값이 범위를 벗어났습니다.');
      out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { z85encode, z85decode });

  DL.addTool('base', {
    id: 'z85', name: 'Z85', short: 'ZeroMQ Base85',
    desc: 'ZeroMQ에서 정의한 Base85 변형입니다. 따옴표와 역슬래시를 피해 소스 코드에 넣기 쉽습니다. 입력은 4바이트 배수여야 합니다.',
    options: [{ ...IN, default: 'hex' }],
    encode: (s, o) => z85encode(readBytes(s, o.inFmt)),
    decode: (s) => z85decode(s),
  });
})(globalThis.DecryptLab);
