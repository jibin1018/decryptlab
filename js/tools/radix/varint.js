/* 진법·데이터 표현 › VarInt · ZigZag */
(function (DL) {
  'use strict';
  const { toHex, fromHex, parseBig } = DL.kits.radix;

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

  DL.addTool('radix', {
    id: 'varint', name: 'VarInt · ZigZag', short: 'Protobuf 가변 길이 정수',
    desc: '7비트씩 끊어 저장하는 Protocol Buffers의 가변 길이 정수입니다. ZigZag를 켜면 sint32/sint64 방식(음수를 작은 양수로 매핑)을 사용합니다.',
    modes: [
      { id: 'encode', label: '인코딩', inLabel: '정수 목록', placeholder: '예: 1 150 300' },
      { id: 'decode', label: '디코딩', inLabel: '16진수 바이트', placeholder: '예: 96 01' },
    ],
    options: [{ id: 'zigzag', label: 'ZigZag (sint)', type: 'checkbox', default: false }],
    encode: (s, o) => varintEncode(s, o.zigzag),
    decode: (s, o) => varintDecode(s, o.zigzag),
  });
})(globalThis.DecryptLab);
