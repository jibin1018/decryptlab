/* 압축·데이터 복원 › LZ4 해제 (프레임 · 레거시 · 블록) */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption } = DL.kits.compress;

  class Grow {
    constructor(n = 1024) { this.buf = new Uint8Array(n); this.len = 0; }
    ensure(n) { if (this.len + n > this.buf.length) { const b = new Uint8Array(Math.max(this.buf.length * 2, this.len + n)); b.set(this.buf.subarray(0, this.len)); this.buf = b; } }
    push(arr) { this.ensure(arr.length); this.buf.set(arr, this.len); this.len += arr.length; }
    result() { return this.buf.slice(0, this.len); }
  }
  const LIMIT = 256 * 1024 * 1024;
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  function lz4Block(src, out) {
    let p = 0;
    const len = () => { let n = 0, b; do { if (p >= src.length) throw new Error('LZ4 블록이 잘렸습니다.'); b = src[p++]; n += b; } while (b === 255); return n; };
    while (p < src.length) {
      const token = src[p++];
      let lit = token >> 4;
      if (lit === 15) lit += len();
      if (p + lit > src.length) throw new Error('LZ4 리터럴 길이가 데이터를 넘습니다.');
      out.push(src.subarray(p, p + lit)); p += lit;
      if (p >= src.length) break;
      const off = src[p] | (src[p + 1] << 8); p += 2;
      if (!off || off > out.len) throw new Error('LZ4 매치 오프셋이 올바르지 않습니다 — LZ4 데이터가 아니거나 손상되었습니다.');
      let ml = token & 15;
      if (ml === 15) ml += len();
      ml += 4;
      if (out.len + ml > LIMIT) throw new Error('해제 결과가 256 MB를 넘어 중단했습니다.');
      out.ensure(ml);
      for (let i = 0; i < ml; i++) out.buf[out.len] = out.buf[out.len++ - off];
    }
  }
  function lz4Decompress(b, mode = 'auto') {
    const out = new Grow(Math.max(1024, b.length * 3));
    const isFrame = u32(b, 0) === 0x184d2204, isLegacy = u32(b, 0) === 0x184c2102;
    if (mode === 'block' || (mode === 'auto' && !isFrame && !isLegacy)) { lz4Block(b, out); return out.result(); }
    let p = 0;
    while (p + 4 <= b.length) {
      const magic = u32(b, p);
      if (magic === 0x184c2102) { // 레거시 프레임: 압축 블록만 이어짐
        p += 4;
        while (p + 4 <= b.length && u32(b, p) !== 0x184d2204 && u32(b, p) !== 0x184c2102) { const n = u32(b, p); p += 4; lz4Block(b.subarray(p, p + n), out); p += n; }
        continue;
      }
      if ((magic & 0xfffffff0) === 0x184d2a50) { p += 8 + u32(b, p + 4); continue; } // 건너뛰기 프레임
      if (magic !== 0x184d2204) throw new Error('LZ4 프레임 매직 넘버(04 22 4D 18)가 없습니다. "블록"으로 바꿔 보세요.');
      const flg = b[p + 4];
      if (flg >> 6 !== 1) throw new Error('지원하지 않는 LZ4 프레임 버전입니다.');
      p += 6 + (flg & 0x08 ? 8 : 0) + (flg & 0x01 ? 4 : 0) + 1;
      for (;;) {
        if (p + 4 > b.length) throw new Error('LZ4 프레임이 잘렸습니다 (끝 표시가 없음).');
        const raw = u32(b, p); p += 4;
        if (raw === 0) break;
        const size = raw & 0x7fffffff;
        const data = b.subarray(p, p + size); p += size;
        if (raw & 0x80000000) out.push(data); else lz4Block(data, out);
        if (flg & 0x10) p += 4;
      }
      if (flg & 0x04) p += 4;
    }
    return out.result();
  }
  DL.fn.lz4Decompress = lz4Decompress;

  DL.addTool('compress', {
    id: 'lz4', name: 'LZ4 해제', short: '프레임 · 레거시 · 블록',
    desc: '압축 속도가 매우 빠른 LZ4 데이터를 해제합니다. .lz4 파일(프레임 형식), 레거시 형식, 헤더 없는 블록을 지원합니다. 게임 리소스나 로그, 커널 이미지에서 자주 보입니다.',
    fileInput: true, slow: true,
    modes: [{ id: 'decompress', label: '압축 해제', inLabel: 'LZ4 데이터', outLabel: '원본' }],
    options: [
      { id: 'mode', label: '형식', type: 'select', default: 'auto', choices: [['auto', '자동'], ['frame', '프레임 (.lz4)'], ['block', '블록 (헤더 없음)']] },
      fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']),
      fmtOption('outFmt', '출력 형식', 'text', ['text', 'hex', 'base64']),
    ],
    decompress: (s, o) => {
      const out = lz4Decompress(readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt), o.mode);
      return o.outFmt === 'text' ? out : formatBytes(out, o.outFmt);
    },
  });
})(globalThis.DecryptLab);
