/* Base 계열 › Ascii85 */
(function (DL) {
  'use strict';
  const { readBytes, IN } = DL.kits.base;

  function a85encode(bytes, { wrap = true } = {}) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 4) {
      const chunk = bytes.subarray(i, i + 4);
      const n = chunk.length;
      let v = 0;
      for (let j = 0; j < 4; j++) v = v * 256 + (chunk[j] || 0);
      if (n === 4 && v === 0) { out += 'z'; continue; }
      const enc = [];
      for (let j = 0; j < 5; j++) { enc.unshift(String.fromCharCode((v % 85) + 33)); v = Math.floor(v / 85); }
      out += enc.slice(0, n + 1).join('');
    }
    return wrap ? `<~${out}~>` : out;
  }
  function a85decode(s) {
    let clean = s.replace(/\s/g, '');
    if (clean.startsWith('<~')) clean = clean.slice(2);
    if (clean.endsWith('~>')) clean = clean.slice(0, -2);
    const out = [];
    let group = [];
    const flush = (g, n) => {
      let v = 0;
      for (const c of g) v = v * 85 + (c - 33);
      if (v > 0xffffffff) throw new Error('Ascii85 그룹 값이 범위를 벗어났습니다.');
      out.push(...[(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].slice(0, n));
    };
    for (const ch of clean) {
      if (ch === 'z' && group.length === 0) { out.push(0, 0, 0, 0); continue; }
      const c = ch.charCodeAt(0);
      if (c < 33 || c > 117) throw new Error(`Ascii85 문자가 아닙니다: "${ch}"`);
      group.push(c);
      if (group.length === 5) { flush(group, 4); group = []; }
    }
    if (group.length === 1) throw new Error('Ascii85 마지막 그룹이 너무 짧습니다.');
    if (group.length) {
      const n = group.length - 1;
      while (group.length < 5) group.push(117);
      flush(group, n);
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { a85encode, a85decode });

  DL.addTool('base', {
    id: 'base85', name: 'Ascii85', short: 'Base85 · PDF/PostScript',
    desc: '4바이트를 5개의 문자로 표현해 Base64보다 효율적입니다. PDF와 PostScript에서 사용하며 <~ ~> 구분자를 붙입니다.',
    options: [IN, { id: 'wrap', label: '<~ ~> 구분자 포함', type: 'checkbox', default: true, mode: 'encode' }],
    encode: (s, o) => a85encode(readBytes(s, o.inFmt), o),
    decode: (s) => a85decode(s),
  });
})(globalThis.DecryptLab);
