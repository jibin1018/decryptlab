/* 진법·데이터 표현 › 정수·엔디안 해석 */
(function (DL) {
  'use strict';
  const { toHex, fromHex, parseBig, bigToRadix } = DL.kits.radix;

  function interpretBytes(bytes) {
    const rows = [];
    const view = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
    const show = (label, fn) => {
      try { rows.push(`${label.padEnd(16)} ${fn()}`); } catch { /* 길이 부족 */ }
    };
    const n = bytes.length;
    rows.push(`입력 ${n} B: ${toHex(bytes, false, ' ')}`, `역순 바이트      ${toHex(bytes.slice().reverse(), false, ' ')}`, '');
    if (n >= 1) { show('uint8', () => bytes[0]); show('int8', () => view(bytes).getInt8(0)); }
    for (const [w, name] of [[2, '16'], [4, '32'], [8, '64']]) {
      if (n < w) continue;
      const dv = view(bytes);
      const getU = (le) => (w === 8 ? dv.getBigUint64(0, le) : w === 4 ? dv.getUint32(0, le) : dv.getUint16(0, le));
      const getI = (le) => (w === 8 ? dv.getBigInt64(0, le) : w === 4 ? dv.getInt32(0, le) : dv.getInt16(0, le));
      rows.push('');
      show(`uint${name} LE`, () => String(getU(true)));
      show(`uint${name} BE`, () => String(getU(false)));
      show(`int${name} LE`, () => String(getI(true)));
      show(`int${name} BE`, () => String(getI(false)));
      if (w === 4) { show('float32 LE', () => dv.getFloat32(0, true)); show('float32 BE', () => dv.getFloat32(0, false)); }
      if (w === 8) { show('float64 LE', () => dv.getFloat64(0, true)); show('float64 BE', () => dv.getFloat64(0, false)); }
    }
    if (n > 8) rows.push('', `※ 앞 8바이트만 해석했습니다.`);
    return rows.join('\n');
  }
  function intToBytes(str) {
    const n = parseBig(str, /^-?0x/i.test(str.trim()) ? 16 : 10);
    const rows = [`값: ${n}  (16진수 ${bigToRadix(n, 16)})`, ''];
    for (const bits of [8, 16, 32, 64]) {
      const min = -(1n << BigInt(bits - 1)), max = (1n << BigInt(bits)) - 1n;
      if (n < min || n > max) { rows.push(`${String(bits).padStart(2)}비트  범위 초과`); continue; }
      const u = n < 0n ? (1n << BigInt(bits)) + n : n; // 2의 보수
      const be = [];
      for (let i = bits / 8 - 1; i >= 0; i--) be.push(Number((u >> BigInt(i * 8)) & 255n));
      const beb = Uint8Array.from(be);
      rows.push(`${String(bits).padStart(2)}비트  BE ${toHex(beb, false, ' ').padEnd(24)} LE ${toHex(beb.slice().reverse(), false, ' ')}`);
    }
    if (n < 0n) rows.push('', '음수는 2의 보수로 표현했습니다.');
    return rows.join('\n');
  }
  DL.fn.interpretBytes = interpretBytes;

  DL.addTool('radix', {
    id: 'integer', name: '정수·엔디안 해석', short: 'LE/BE · 부호 · 2의 보수',
    desc: '바이트를 8/16/32/64비트 부호 있는·없는 정수로, 리틀/빅 엔디안 모두 해석합니다. 반대로 정수를 2의 보수 바이트로 바꿀 수도 있습니다.',
    modes: [
      { id: 'decode', label: '바이트 → 정수', inLabel: '16진수 바이트', placeholder: '예: ff ff ff fe' },
      { id: 'encode', label: '정수 → 바이트', inLabel: '정수', placeholder: '예: -2, 3735928559, 0xdeadbeef' },
    ],
    decode: (s) => interpretBytes(fromHex(s)),
    encode: (s) => intToBytes(s),
  });
})(globalThis.DecryptLab);
