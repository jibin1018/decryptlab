/* Base 계열 › Base45 (RFC 9285) */
(function (DL) {
  'use strict';
  const { readBytes, IN } = DL.kits.base;

  const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function b45encode(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 2) {
      if (i + 1 < bytes.length) {
        let n = bytes[i] * 256 + bytes[i + 1];
        const c = n % 45; n = (n - c) / 45;
        const d = n % 45; const e = (n - d) / 45;
        out += B45[c] + B45[d] + B45[e];
      } else {
        const n = bytes[i];
        out += B45[n % 45] + B45[Math.floor(n / 45)];
      }
    }
    return out;
  }
  function b45decode(s) {
    const clean = s.replace(/[\r\n\t]/g, '');
    const vals = Array.from(clean, (c) => {
      const i = B45.indexOf(c);
      if (i < 0) throw new Error(`Base45 문자가 아닙니다: "${c}"`);
      return i;
    });
    if (vals.length % 3 === 1) throw new Error('Base45 길이가 올바르지 않습니다.');
    const out = [];
    for (let i = 0; i < vals.length; i += 3) {
      if (i + 2 < vals.length) {
        const n = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 2025;
        if (n > 0xffff) throw new Error('Base45 값이 범위를 벗어났습니다.');
        out.push(n >> 8, n & 255);
      } else {
        const n = vals[i] + vals[i + 1] * 45;
        if (n > 0xff) throw new Error('Base45 값이 범위를 벗어났습니다.');
        out.push(n);
      }
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { b45encode, b45decode });

  DL.addTool('base', {
    id: 'base45', name: 'Base45', short: 'RFC 9285 · QR 코드',
    desc: 'QR 코드의 영숫자 모드에 맞춘 인코딩입니다. EU 디지털 코로나 증명서(EU DCC)에서 사용되어 알려졌습니다.',
    options: [IN],
    encode: (s, o) => b45encode(readBytes(s, o.inFmt)),
    decode: (s) => b45decode(s),
  });
})(globalThis.DecryptLab);
