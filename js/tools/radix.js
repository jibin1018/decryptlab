/* 진법·데이터 표현 */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex } = DL;

  const SEP = { space: ' ', none: '', comma: ', ', newline: '\n' };
  const SEP_OPTION = {
    id: 'sep', label: '구분자', type: 'select', default: 'space', mode: 'encode',
    choices: [['space', '공백'], ['none', '없음'], ['comma', '쉼표'], ['newline', '줄바꿈']],
  };

  function radixEncode(bytes, radix, width, sep) {
    return Array.from(bytes, (b) => b.toString(radix).padStart(width, '0')).join(SEP[sep] ?? ' ');
  }
  function radixDecode(s, radix) {
    const re = radix === 2 ? /[^01]/ : radix === 8 ? /[^0-7]/ : /[^0-9]/;
    let tokens = s.trim().split(/[\s,;]+/).filter(Boolean);
    if (tokens.length === 1 && radix === 2 && tokens[0].length > 8) {
      if (tokens[0].length % 8) throw new Error('구분자 없는 2진수는 8의 배수 길이여야 합니다.');
      tokens = tokens[0].match(/.{8}/g);
    }
    if (tokens.length === 1 && radix === 8 && tokens[0].length > 3 && tokens[0].length % 3 === 0) tokens = tokens[0].match(/.{3}/g);
    return new Uint8Array(tokens.map((t) => {
      if (re.test(t)) throw new Error(`올바르지 않은 값: "${t}"`);
      const v = parseInt(t, radix);
      if (v > 255) throw new Error(`바이트 범위(0–255)를 벗어난 값: "${t}"`);
      return v;
    }));
  }

  /* ---------- 임의 진법 정수 변환 ---------- */
  const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  function parseBig(str, radix) {
    let s = str.trim().replace(/[_\s]/g, '');
    let neg = false;
    if (s.startsWith('-')) { neg = true; s = s.slice(1); }
    if (radix === 16) s = s.replace(/^0x/i, '');
    if (radix === 2) s = s.replace(/^0b/i, '');
    if (radix === 8) s = s.replace(/^0o/i, '');
    if (!s) throw new Error('숫자를 입력하세요.');
    const alpha = radix <= 36 ? DIGITS.slice(0, radix) : DIGITS.slice(0, radix);
    let n = 0n;
    for (const c of s) {
      const d = (radix <= 36 ? alpha.indexOf(c.toLowerCase()) : alpha.indexOf(c));
      if (d < 0) throw new Error(`${radix}진수에 쓸 수 없는 문자: "${c}"`);
      n = n * BigInt(radix) + BigInt(d);
    }
    return neg ? -n : n;
  }
  function bigToRadix(n, radix) {
    if (n === 0n) return '0';
    const neg = n < 0n;
    let v = neg ? -n : n, s = '';
    const r = BigInt(radix);
    while (v > 0n) { s = DIGITS[Number(v % r)] + s; v /= r; }
    return (neg ? '-' : '') + s;
  }

  /* ---------- IEEE 754 ---------- */
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

  /* ---------- 정수 / 엔디안 해석 ---------- */
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

  /* ---------- VarInt / ZigZag ---------- */
  const zigzagEnc = (n) => (n >= 0n ? n << 1n : (-n << 1n) - 1n);
  const zigzagDec = (n) => ((n & 1n) ? -((n + 1n) >> 1n) : n >> 1n);
  function varintEncode(s, zigzag) {
    const nums = s.trim().split(/[\s,;]+/).filter(Boolean).map((t) => parseBig(t, 10));
    return nums.map((n0) => {
      let n = zigzag ? zigzagEnc(n0) : n0;
      if (n < 0n) n += 1n << 64n; // protobuf int64 음수
      const out = [];
      do {
        let b = Number(n & 0x7fn);
        n >>= 7n;
        if (n > 0n) b |= 0x80;
        out.push(b);
      } while (n > 0n);
      return toHex(Uint8Array.from(out), false, ' ');
    }).join('\n');
  }
  function varintDecode(s, zigzag) {
    const bytes = fromHex(s);
    const out = [];
    let cur = 0n, shift = 0n, start = 0;
    bytes.forEach((b, i) => {
      cur |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if (!(b & 0x80)) {
        const v = zigzag ? zigzagDec(cur) : cur;
        out.push(`${toHex(bytes.slice(start, i + 1), false, ' ').padEnd(30)} → ${v}`);
        cur = 0n; shift = 0n; start = i + 1;
      }
    });
    if (start < bytes.length) out.push(`${toHex(bytes.slice(start), false, ' ').padEnd(30)} → (불완전 — 마지막 바이트에 계속 비트가 있음)`);
    return out.join('\n');
  }

  Object.assign(DL.fn, { radixEncode, radixDecode, parseBig, bigToRadix, interpretBytes });

  const BASES = [['2', '2진수'], ['8', '8진수'], ['10', '10진수'], ['16', '16진수'], ['36', '36진수'], ['62', '62진수']];

  DL.addCategory({
    id: 'radix',
    name: '진법·데이터 표현',
    desc: '2·8·10·16진수 바이트부터 IEEE 754 부동소수점, 엔디안·정수 해석, Protobuf VarInt까지',
    color: 'green',
    tools: [
      {
        id: 'binary', name: '2진수', short: '8비트 단위 · ASCII Binary',
        desc: 'UTF-8 바이트를 8자리 2진수로 표현합니다. 디코딩 시 구분자 없이 이어 붙인 비트열도 8자리씩 나눠 처리합니다.',
        options: [SEP_OPTION],
        encode: (s, o) => radixEncode(utf8(s), 2, 8, o.sep),
        decode: (s) => radixDecode(s, 2),
      },
      {
        id: 'octal', name: '8진수', short: '3자리 단위',
        desc: 'UTF-8 바이트를 3자리 8진수로 표현합니다.',
        options: [SEP_OPTION],
        encode: (s, o) => radixEncode(utf8(s), 8, 3, o.sep),
        decode: (s) => radixDecode(s, 8),
      },
      {
        id: 'decimal', name: '10진수 바이트', short: '0–255 값 목록 · ASCII Decimal',
        desc: 'UTF-8 바이트를 0–255 사이의 10진수로 표현합니다. 바이트 배열을 그대로 붙여 넣을 때 유용합니다.',
        options: [{ ...SEP_OPTION, default: 'comma' }],
        encode: (s, o) => radixEncode(utf8(s), 10, 0, o.sep),
        decode: (s) => radixDecode(s, 10),
      },
      {
        id: 'codepoint', name: '코드 포인트', short: '문자 단위 10진/16진',
        desc: '바이트가 아니라 문자 하나하나의 유니코드 번호를 보여줍니다. 한글 "가"는 44032(0xAC00)입니다.',
        options: [{ id: 'base', label: '진법', type: 'select', default: '10', mode: 'encode', choices: [['10', '10진수'], ['16', '16진수 (0x)']] }],
        encode: (s, o) => Array.from(s, (ch) => {
          const cp = ch.codePointAt(0);
          return o.base === '16' ? '0x' + cp.toString(16).toUpperCase() : String(cp);
        }).join(' '),
        decode: (s) => s.trim().split(/[\s,;]+/).filter(Boolean).map((t) => {
          const v = /^(0x|u\+)/i.test(t) ? parseInt(t.slice(2), 16) : parseInt(t, 10);
          if (!Number.isFinite(v) || v < 0 || v > 0x10ffff) throw new Error(`올바르지 않은 코드 포인트: "${t}"`);
          return String.fromCodePoint(v);
        }).join(''),
      },
      {
        id: 'baseconv', name: '진법 변환기', short: '정수 2·8·10·16·36·62진수',
        desc: '큰 정수도 정확하게(BigInt) 진법 사이를 변환합니다. 한 줄에 하나씩 여러 값을 넣을 수 있습니다.',
        modes: [{ id: 'run', label: '변환', inLabel: '숫자', placeholder: '변환할 정수 (예: 255, 0xff)' }],
        options: [{ id: 'from', label: '입력 진법', type: 'select', default: '10', choices: BASES }],
        run: (s, o) => s.split(/\r?\n/).filter((l) => l.trim()).map((line) => {
          const n = parseBig(line, Number(o.from));
          return BASES.map(([r, l]) => `${l.padEnd(5)} ${bigToRadix(n, Number(r))}`).join('\n');
        }).join('\n\n'),
      },
      {
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
      },
      {
        id: 'integer', name: '정수·엔디안 해석', short: 'LE/BE · 부호 · 2의 보수',
        desc: '바이트를 8/16/32/64비트 부호 있는·없는 정수로, 리틀/빅 엔디안 모두 해석합니다. 반대로 정수를 2의 보수 바이트로 바꿀 수도 있습니다.',
        modes: [
          { id: 'decode', label: '바이트 → 정수', inLabel: '16진수 바이트', placeholder: '예: ff ff ff fe' },
          { id: 'encode', label: '정수 → 바이트', inLabel: '정수', placeholder: '예: -2, 3735928559, 0xdeadbeef' },
        ],
        decode: (s) => interpretBytes(fromHex(s)),
        encode: (s) => intToBytes(s),
      },
      {
        id: 'varint', name: 'VarInt · ZigZag', short: 'Protobuf 가변 길이 정수',
        desc: '7비트씩 끊어 저장하는 Protocol Buffers의 가변 길이 정수입니다. ZigZag를 켜면 sint32/sint64 방식(음수를 작은 양수로 매핑)을 사용합니다.',
        modes: [
          { id: 'encode', label: '인코딩', inLabel: '정수 목록', placeholder: '예: 1 150 300' },
          { id: 'decode', label: '디코딩', inLabel: '16진수 바이트', placeholder: '예: 96 01' },
        ],
        options: [{ id: 'zigzag', label: 'ZigZag (sint)', type: 'checkbox', default: false }],
        encode: (s, o) => varintEncode(s, o.zigzag),
        decode: (s, o) => varintDecode(s, o.zigzag),
      },
    ],
  });
})(globalThis.DecryptLab);
