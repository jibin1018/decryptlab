/* Base 계열 › basE91 */
(function (DL) {
  'use strict';
  const { readBytes, IN } = DL.kits.base;

  const B91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
  function b91encode(bytes) {
    let b = 0, n = 0, out = '';
    for (const byte of bytes) {
      b |= byte << n; n += 8;
      if (n > 13) {
        let v = b & 8191;
        if (v > 88) { b >>>= 13; n -= 13; } else { v = b & 16383; b >>>= 14; n -= 14; }
        out += B91[v % 91] + B91[Math.floor(v / 91)];
      }
    }
    if (n) {
      out += B91[b % 91];
      if (n > 7 || b > 90) out += B91[Math.floor(b / 91)];
    }
    return out;
  }
  function b91decode(s) {
    let v = -1, b = 0, n = 0;
    const out = [];
    for (const c of s) {
      const d = B91.indexOf(c);
      if (d < 0) {
        if (/\s/.test(c)) continue;
        throw new Error(`basE91 문자가 아닙니다: "${c}"`);
      }
      if (v < 0) v = d;
      else {
        v += d * 91;
        b |= v << n;
        n += (v & 8191) > 88 ? 13 : 14;
        do { out.push(b & 255); b >>>= 8; n -= 8; } while (n > 7);
        v = -1;
      }
    }
    if (v > -1) out.push((b | (v << n)) & 255);
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { b91encode, b91decode });

  DL.addTool('base', {
    id: 'base91', name: 'basE91', short: 'Base64보다 약 20% 짧음',
    desc: '91개의 출력 가능한 ASCII 문자를 사용해 Base64보다 결과가 짧습니다. CTF에서 종종 등장합니다.',
    options: [IN],
    encode: (s, o) => b91encode(readBytes(s, o.inFmt)),
    decode: (s) => b91decode(s),
  });
})(globalThis.DecryptLab);
