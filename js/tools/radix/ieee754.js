/* 진법·데이터 표현 › IEEE 754 부동소수점 */
(function (DL) {
  'use strict';
  const { toHex, fromHex } = DL.kits.radix;

  function floatBits(value, bits) {
    const buf = new DataView(new ArrayBuffer(bits / 8));
    bits === 32 ? buf.setFloat32(0, value) : buf.setFloat64(0, value);
    const bytes = new Uint8Array(buf.buffer);
    const bin = Array.from(bytes, (b) => b.toString(2).padStart(8, '0')).join('');
    const eLen = bits === 32 ? 8 : 11;
    const stored = bits === 32 ? buf.getFloat32(0) : buf.getFloat64(0);
    const exp = parseInt(bin.substr(1, eLen), 2);
    const bias = bits === 32 ? 127 : 1023;
    const kind = exp === 0 ? (/1/.test(bin.slice(1 + eLen)) ? '비정규화 수' : '0') : exp === (1 << eLen) - 1 ? (/1/.test(bin.slice(1 + eLen)) ? 'NaN' : '무한대') : '정규화 수';
    return [
      `■ ${bits === 32 ? 'Float32 (단정밀도)' : 'Float64 (배정밀도)'}`,
      `  Hex (BE)   ${toHex(bytes)}`,
      `  Hex (LE)   ${toHex(bytes.slice().reverse())}`,
      `  부호       ${bin[0]}  (${bin[0] === '1' ? '음수' : '양수'})`,
      `  지수       ${bin.substr(1, eLen)}  (${exp}${kind === '정규화 수' ? `, 실제 2^${exp - bias}` : ''})`,
      `  가수       ${bin.slice(1 + eLen)}`,
      `  분류       ${kind}`,
      `  저장된 값  ${Object.is(stored, -0) ? '-0' : stored.toPrecision(bits === 32 ? 9 : 17).replace(/\.?0+(e|$)/, '$1')}${stored !== value && !Number.isNaN(value) ? '  (정밀도 손실)' : ''}`,
    ].join('\n');
  }
  function ieeeDecode(s, order) {
    const t = s.trim();
    let bytes;
    if (/^[01\s]+$/.test(t) && t.replace(/\s/g, '').length >= 32) {
      const b = t.replace(/\s/g, '');
      if (b.length !== 32 && b.length !== 64) throw new Error('2진수는 32비트 또는 64비트여야 합니다.');
      bytes = new Uint8Array(b.match(/.{8}/g).map((x) => parseInt(x, 2)));
    } else bytes = fromHex(t);
    if (bytes.length !== 4 && bytes.length !== 8) throw new Error('4바이트(Float32) 또는 8바이트(Float64) 16진수를 입력하세요.');
    if (order === 'le') bytes = bytes.slice().reverse();
    const dv = new DataView(bytes.buffer);
    const v = bytes.length === 4 ? dv.getFloat32(0) : dv.getFloat64(0);
    return `${Object.is(v, -0) ? '-0' : String(v)}\n\n${floatBits(v, bytes.length * 8)}`;
  }

  DL.addTool('radix', {
    id: 'ieee754', name: 'IEEE 754 부동소수점', short: 'Float32/64 비트 구조',
    desc: '실수를 부호·지수·가수 비트로 분해해 보여주고, 메모리 덤프의 4/8바이트를 실수로 해석합니다. 0.1 + 0.2 문제 같은 정밀도 손실도 확인할 수 있습니다.',
    modes: [
      { id: 'encode', label: '숫자 → 비트', inLabel: '실수', placeholder: '예: 3.14, -0.1, 1e-10' },
      { id: 'decode', label: '비트 → 숫자', inLabel: '16진수 또는 2진수', placeholder: '예: 40490fdb (Float32), 400921fb54442d18 (Float64)' },
    ],
    options: [{ id: 'order', label: '바이트 순서', type: 'select', default: 'be', mode: 'decode', choices: [['be', '빅 엔디안'], ['le', '리틀 엔디안']] }],
    encode: (s) => {
      const v = Number(s.trim());
      if (s.trim() === '' || (Number.isNaN(v) && !/^nan$/i.test(s.trim()))) throw new Error('숫자를 입력하세요.');
      return `${floatBits(v, 32)}\n\n${floatBits(v, 64)}`;
    },
    decode: (s, o) => ieeeDecode(s, o.order),
  });
})(globalThis.DecryptLab);
