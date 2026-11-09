/* 압축·데이터 복원 › XZ · LZMA · Bzip2 해제 (순수 JS 디코더) */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption } = DL.kits.compress;

  /* ---------- LZMA / XZ 해제 (범위 디코더 + 상태 기계, LzmaSpec.cpp 기반) ---------- */
  const DECOMP_CAP = 256 * 1024 * 1024;
  const LZ_PROB = 1024;
  class RangeDec {
    constructor(buf, pos) {
      this.buf = buf; this.pos = pos + 1; this.range = 0xFFFFFFFF >>> 0; this.code = 0;
      for (let i = 0; i < 4; i++) this.code = ((this.code << 8) | this.buf[this.pos++]) >>> 0;
    }
    norm() { if (this.range < (1 << 24)) { this.range = (this.range << 8) >>> 0; this.code = ((this.code << 8) | (this.buf[this.pos++] | 0)) >>> 0; } }
    bit(probs, i) {
      const p = probs[i], bound = ((this.range >>> 11) * p) >>> 0; let s;
      if ((this.code >>> 0) < bound) { this.range = bound; probs[i] = p + ((2048 - p) >> 5); s = 0; }
      else { this.range = (this.range - bound) >>> 0; this.code = (this.code - bound) >>> 0; probs[i] = p - (p >> 5); s = 1; }
      this.norm(); return s;
    }
    direct(n) { let res = 0; do { this.range = this.range >>> 1; this.code = (this.code - this.range) >>> 0; const t = (0 - (this.code >>> 31)) >>> 0; this.code = (this.code + (this.range & t)) >>> 0; this.norm(); res = ((res << 1) + t + 1) >>> 0; } while (--n); return res >>> 0; }
  }
  const btree = (rc, p, off, nb) => { let m = 1; for (let i = 0; i < nb; i++) m = (m << 1) | rc.bit(p, off + m); return m - (1 << nb); };
  const btreeRev = (rc, p, off, nb) => { let m = 1, s = 0; for (let i = 0; i < nb; i++) { const b = rc.bit(p, off + m); m = (m << 1) | b; s |= b << i; } return s >>> 0; };
  class Lzma {
    constructor() { this.out = []; this.dictStart = 0; }
    props(lc, lp, pb) { this.lc = lc; this.lp = lp; this.pb = pb; }
    resetState() {
      this.state = 0; this.rep0 = 0; this.rep1 = 0; this.rep2 = 0; this.rep3 = 0;
      const mk = (n) => { const a = new Uint16Array(n); a.fill(LZ_PROB); return a; };
      this.IsMatch = mk(192); this.IsRep = mk(12); this.IsRepG0 = mk(12); this.IsRepG1 = mk(12); this.IsRepG2 = mk(12); this.IsRep0Long = mk(192);
      this.PosSlot = mk(256); this.SpecPos = mk(115); this.Align = mk(16);
      this.LenCh = mk(2); this.LenLo = mk(128); this.LenMi = mk(128); this.LenHi = mk(256);
      this.RepCh = mk(2); this.RepLo = mk(128); this.RepMi = mk(128); this.RepHi = mk(256);
      this.Lit = mk(0x300 << (this.lc + this.lp));
    }
    len(rc, rep, ps) {
      const ch = rep ? this.RepCh : this.LenCh, lo = rep ? this.RepLo : this.LenLo, mi = rep ? this.RepMi : this.LenMi, hi = rep ? this.RepHi : this.LenHi;
      if (rc.bit(ch, 0) === 0) return btree(rc, lo, ps << 3, 3);
      if (rc.bit(ch, 1) === 0) return 8 + btree(rc, mi, ps << 3, 3);
      return 16 + btree(rc, hi, 0, 8);
    }
    run(rc, limit) {
      const pbMask = (1 << this.pb) - 1, lpMask = (1 << this.lp) - 1, lc = this.lc, out = this.out;
      for (;;) {
        if (limit >= 0 && out.length >= limit) break;
        if (out.length > DECOMP_CAP) throw new Error('해제 결과가 256 MB를 넘어 중단했습니다.');
        const ps = out.length & pbMask;
        if (rc.bit(this.IsMatch, (this.state << 4) + ps) === 0) {
          const prev = out.length > this.dictStart ? out[out.length - 1] : 0;
          const litState = ((out.length & lpMask) << lc) + (prev >> (8 - lc));
          const base = 0x300 * litState; let sym = 1;
          if (this.state >= 7) {
            let mb = out[out.length - this.rep0 - 1];
            do { const matchBit = (mb >> 7) & 1; mb = (mb << 1) & 0xff; const bit = rc.bit(this.Lit, base + ((1 + matchBit) << 8) + sym); sym = (sym << 1) | bit; if (matchBit !== bit) break; } while (sym < 0x100);
          }
          while (sym < 0x100) sym = (sym << 1) | rc.bit(this.Lit, base + sym);
          out.push(sym & 0xff);
          this.state = this.state < 4 ? 0 : this.state < 10 ? this.state - 3 : this.state - 6;
          continue;
        }
        let len;
        if (rc.bit(this.IsRep, this.state) === 1) {
          if (rc.bit(this.IsRepG0, this.state) === 0) {
            if (rc.bit(this.IsRep0Long, (this.state << 4) + ps) === 0) { this.state = this.state < 7 ? 9 : 11; out.push(out[out.length - this.rep0 - 1]); continue; }
          } else {
            let dist;
            if (rc.bit(this.IsRepG1, this.state) === 0) dist = this.rep1;
            else { if (rc.bit(this.IsRepG2, this.state) === 0) dist = this.rep2; else { dist = this.rep3; this.rep3 = this.rep2; } this.rep2 = this.rep1; }
            this.rep1 = this.rep0; this.rep0 = dist;
          }
          len = this.len(rc, 1, ps); this.state = this.state < 7 ? 8 : 11;
        } else {
          this.rep3 = this.rep2; this.rep2 = this.rep1; this.rep1 = this.rep0;
          len = this.len(rc, 0, ps); this.state = this.state < 7 ? 7 : 10;
          const lenState = len < 4 ? len : 3, posSlot = btree(rc, this.PosSlot, lenState * 64, 6);
          if (posSlot < 4) this.rep0 = posSlot;
          else {
            const nd = (posSlot >> 1) - 1; let dist = ((2 | (posSlot & 1)) << nd) >>> 0;
            if (posSlot < 14) dist = (dist + btreeRev(rc, this.SpecPos, dist - posSlot, nd)) >>> 0;
            else { dist = (dist + (rc.direct(nd - 4) << 4)) >>> 0; dist = (dist + btreeRev(rc, this.Align, 0, 4)) >>> 0; }
            this.rep0 = dist >>> 0;
          }
          if (this.rep0 === 0xFFFFFFFF) break;
        }
        len += 2;
        for (let k = 0; k < len; k++) { if (limit >= 0 && out.length >= limit) break; out.push(out[out.length - this.rep0 - 1]); }
      }
    }
  }
  function lzmaAlone(buf) {
    if (buf.length < 13) throw new Error('.lzma 헤더가 너무 짧습니다.');
    const pb0 = buf[0]; if (pb0 >= 9 * 5 * 5) throw new Error('LZMA 속성 바이트가 올바르지 않습니다 — .lzma 파일이 아닐 수 있습니다.');
    const lc = pb0 % 9, r = Math.floor(pb0 / 9), lp = r % 5, pb = Math.floor(r / 5);
    let size = 0n; for (let i = 0; i < 8; i++) size |= BigInt(buf[5 + i]) << BigInt(8 * i);
    const unknown = size === 0xFFFFFFFFFFFFFFFFn;
    if (!unknown && size > BigInt(DECOMP_CAP)) throw new Error('원본 크기가 256 MB를 넘어 해제하지 않습니다.');
    const lz = new Lzma(); lz.props(lc, lp, pb); lz.resetState();
    lz.run(new RangeDec(buf, 13), unknown ? -1 : Number(size));
    return Uint8Array.from(lz.out);
  }
  const readVarint = (buf, p) => { let n = 0n, sh = 0n, i = p; for (;;) { const b = buf[i++]; n |= BigInt(b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7n; } return [n, i]; };
  function lzma2Decode(buf, p, lz) {
    for (;;) {
      const ctrl = buf[p++];
      if (ctrl === undefined) throw new Error('LZMA2 스트림이 잘렸습니다.');
      if (ctrl === 0) break;
      if (ctrl < 0x80) {
        if (ctrl > 2) throw new Error('LZMA2 제어 바이트가 올바르지 않습니다.');
        if (ctrl === 1) lz.dictStart = lz.out.length;
        const size = ((buf[p] << 8) | buf[p + 1]) + 1; p += 2;
        for (let i = 0; i < size; i++) lz.out.push(buf[p++]);
      } else {
        const unpack = (((ctrl & 0x1f) << 16) | (buf[p] << 8) | buf[p + 1]) + 1; p += 2;
        const comp = ((buf[p] << 8) | buf[p + 1]) + 1; p += 2;
        const reset = (ctrl >> 5) & 3;
        if (reset >= 2) { const pr = buf[p++]; lz.props(pr % 9, Math.floor(pr / 9) % 5, Math.floor(pr / 9 / 5)); }
        if (reset >= 3) lz.dictStart = lz.out.length;
        if (reset >= 1) lz.resetState();
        else if (!lz.IsMatch) throw new Error('LZMA2 첫 청크에 상태 초기화가 없습니다.');
        lz.run(new RangeDec(buf, p), lz.out.length + unpack);
        p += comp;
      }
    }
    return p;
  }
  function xzDecompress(buf) {
    if (!(buf[0] === 0xFD && buf[1] === 0x37 && buf[2] === 0x7A && buf[3] === 0x58 && buf[4] === 0x5A && buf[5] === 0x00)) throw new Error('XZ 매직(FD 37 7A 58 5A 00)이 아닙니다.');
    const checkSize = { 0: 0, 1: 4, 4: 8, 10: 32 }[buf[7] & 0x0f] ?? 4;
    let p = 12; const lz = new Lzma();
    for (;;) {
      const hsByte = buf[p]; if (hsByte === 0 || hsByte === undefined) break;
      const headerSize = (hsByte + 1) * 4, headerStart = p; p += 1;
      const flags = buf[p++], numFilters = (flags & 0x03) + 1;
      if (flags & 0x40) [, p] = readVarint(buf, p);
      if (flags & 0x80) [, p] = readVarint(buf, p);
      let lzma2 = false;
      for (let f = 0; f < numFilters; f++) {
        let id, ps; [id, p] = readVarint(buf, p); [ps, p] = readVarint(buf, p); p += Number(ps);
        if (id === 0x21n) lzma2 = true;
      }
      if (!lzma2) throw new Error('이 XZ 블록은 LZMA2 필터를 쓰지 않아 지원하지 않습니다.');
      p = headerStart + headerSize;
      p = lzma2Decode(buf, p, lz);
      while (p % 4 !== 0) p++;
      p += checkSize;
    }
    return Uint8Array.from(lz.out);
  }

  /* ---------- Bzip2 해제 (BWT + MTF + 허프만) ---------- */
  class BzBits {
    constructor(b) { this.b = b; this.pos = 0; }
    read(n) { let v = 0; while (n > 0) { const take = Math.min(n, 8 - (this.pos & 7)); const avail = 8 - (this.pos & 7); const bits = (this.b[this.pos >> 3] >> (avail - take)) & ((1 << take) - 1); v = v * (1 << take) + bits; this.pos += take; n -= take; } return v; }
    read1() { const bit = (this.b[this.pos >> 3] >> (7 - (this.pos & 7))) & 1; this.pos++; return bit; }
  }
  function bzHuffman(lens, alpha) {
    let minLen = 32, maxLen = 0;
    for (let i = 0; i < alpha; i++) { if (lens[i] > maxLen) maxLen = lens[i]; if (lens[i] < minLen) minLen = lens[i]; }
    const limit = [], base = [], perm = []; let pp = 0;
    for (let len = minLen; len <= maxLen; len++) for (let i = 0; i < alpha; i++) if (lens[i] === len) perm[pp++] = i;
    const cnt = new Array(maxLen + 2).fill(0);
    for (let i = 0; i < alpha; i++) cnt[lens[i] + 1]++;
    for (let i = 1; i < cnt.length; i++) cnt[i] += cnt[i - 1];
    let code = 0;
    for (let len = minLen; len <= maxLen; len++) { code += cnt[len + 1] - cnt[len]; limit[len] = code - 1; code <<= 1; }
    for (let len = minLen + 1; len <= maxLen; len++) base[len] = ((limit[len - 1] + 1) << 1) - cnt[len];
    base[minLen] = -cnt[minLen];
    return { minLen, maxLen, limit, base, perm };
  }
  function bzDecode(rc, t) { let len = t.minLen, code = rc.read(len); while (len <= t.maxLen) { if (code <= t.limit[len]) return t.perm[code - t.base[len]]; len++; code = (code << 1) | rc.read1(); } throw new Error('bzip2 허프만 디코드 실패'); }
  function bzip2Decompress(data) {
    const bits = new BzBits(data);
    if (bits.read(8) !== 0x42 || bits.read(8) !== 0x5a || bits.read(8) !== 0x68) throw new Error('bzip2 헤더(BZh)가 아닙니다.');
    const level = bits.read(8) - 0x30;
    if (level < 1 || level > 9) throw new Error('bzip2 블록 크기 수준이 올바르지 않습니다.');
    const out = [];
    for (;;) {
      const m1 = bits.read(24), m2 = bits.read(24);
      if (m1 === 0x177245 && m2 === 0x385090) { bits.read(32); break; }
      if (m1 !== 0x314159 || m2 !== 0x265359) throw new Error('bzip2 블록 매직이 올바르지 않습니다 — 손상되었거나 bzip2 데이터가 아닙니다.');
      bits.read(32);
      if (bits.read1()) throw new Error('randomized 블록(구형 bzip2)은 지원하지 않습니다.');
      const origPtr = bits.read(24);
      const used16 = bits.read(16), inUse = [];
      for (let i = 0; i < 16; i++) if (used16 & (0x8000 >> i)) { const b16 = bits.read(16); for (let j = 0; j < 16; j++) if (b16 & (0x8000 >> j)) inUse.push(i * 16 + j); }
      const alpha = inUse.length + 2, EOB = alpha - 1;
      const nGroups = bits.read(3), nSelectors = bits.read(15);
      const selMtf = []; for (let i = 0; i < nSelectors; i++) { let j = 0; while (bits.read1()) j++; selMtf.push(j); }
      const gpos = []; for (let i = 0; i < nGroups; i++) gpos.push(i);
      const selectors = [];
      for (const v of selMtf) { let x = v; const t = gpos[x]; while (x > 0) { gpos[x] = gpos[x - 1]; x--; } gpos[0] = t; selectors.push(t); }
      const tables = [];
      for (let g = 0; g < nGroups; g++) { let len = bits.read(5); const lens = []; for (let s = 0; s < alpha; s++) { while (bits.read1()) { if (bits.read1()) len--; else len++; } lens.push(len); } tables.push(bzHuffman(lens, alpha)); }
      const mtf = inUse.slice(), decoded = [];
      let groupNo = -1, groupPos = 0, curT = null, runLen = 0, runShift = 0;
      for (;;) {
        if (groupPos === 0) { groupNo++; groupPos = 50; curT = tables[selectors[groupNo]]; }
        groupPos--;
        const sym = bzDecode(bits, curT);
        if (sym <= 1) { runLen += (sym + 1) << runShift; runShift++; continue; }
        if (runLen > 0) { const b = mtf[0]; for (let k = 0; k < runLen; k++) decoded.push(b); runLen = 0; runShift = 0; }
        if (sym === EOB) break;
        const idx = sym - 1, val = mtf[idx]; mtf.splice(idx, 1); mtf.unshift(val); decoded.push(val);
        if (decoded.length > DECOMP_CAP) throw new Error('해제 결과가 256 MB를 넘어 중단했습니다.');
      }
      const n = decoded.length, cftab = new Int32Array(257);
      for (let i = 0; i < n; i++) cftab[decoded[i] + 1]++;
      for (let i = 1; i <= 256; i++) cftab[i] += cftab[i - 1];
      const tt = new Int32Array(n);
      for (let i = 0; i < n; i++) { const ll = decoded[i]; tt[cftab[ll]] = i; cftab[ll]++; }
      let tPos = tt[origPtr]; const bwt = new Uint8Array(n);
      for (let i = 0; i < n; i++) { bwt[i] = decoded[tPos]; tPos = tt[tPos]; }
      let i = 0;
      while (i < n) {
        const c = bwt[i]; let j = i + 1; while (j < n && j - i < 4 && bwt[j] === c) j++;
        const run = j - i; for (let k = 0; k < run; k++) out.push(c); i = j;
        if (run === 4) { const extra = bwt[i++]; for (let k = 0; k < extra; k++) out.push(c); }
      }
    }
    return Uint8Array.from(out);
  }

  function xzLzmaBzip2(bytes, fmt) {
    const f = fmt === 'auto'
      ? (bytes[0] === 0xFD && bytes[1] === 0x37 && bytes[2] === 0x7A ? 'xz'
        : (bytes[0] === 0x42 && bytes[1] === 0x5A && bytes[2] === 0x68) ? 'bzip2'
          : 'lzma')
      : fmt;
    if (f === 'xz') return { out: xzDecompress(bytes), fmt: f };
    if (f === 'bzip2') return { out: bzip2Decompress(bytes), fmt: f };
    return { out: lzmaAlone(bytes), fmt: f };
  }
  Object.assign(DL.fn, { xzDecompress, lzmaAlone, bzip2Decompress });

  DL.addTool('compress', {
    id: 'xz', name: 'XZ · LZMA · Bzip2 해제', short: '.xz · .lzma · .bz2 압축 풀기',
    desc: '.xz(LZMA2)·.lzma(LZMA alone)·.bz2(bzip2) 압축을 해제합니다. 리눅스 패키지, 커널 이미지, 백업 등에서 자주 보입니다. "자동"은 매직 넘버로 형식을 판별합니다. 순수 자바스크립트 디코더라 큰 파일은 느릴 수 있습니다.',
    fileInput: true, slow: true,
    modes: [{ id: 'decompress', label: '압축 해제', inLabel: '압축 데이터', outLabel: '원본' }],
    options: [
      { id: 'fmt', label: '형식', type: 'select', default: 'auto', choices: [['auto', '자동'], ['xz', 'XZ (.xz)'], ['lzma', 'LZMA (.lzma)'], ['bzip2', 'Bzip2 (.bz2)']] },
      fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']),
      fmtOption('outFmt', '출력 형식', 'text', ['text', 'hex', 'base64']),
    ],
    decompress: (s, o) => {
      const { out } = xzLzmaBzip2(readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt), o.fmt);
      return o.outFmt === 'text' ? out : formatBytes(out, o.outFmt);
    },
  });
})(globalThis.DecryptLab);
