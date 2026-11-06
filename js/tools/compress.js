/* 압축·데이터 복원 (브라우저 내장 Compression Streams 사용) */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, toHex, latin1 } = DL;

  const FORMATS = { gzip: 'gzip', zlib: 'deflate', raw: 'deflate-raw', brotli: 'brotli', zstd: 'zstd' };
  const supported = (fmt) => { try { new DecompressionStream(fmt); return true; } catch { return false; } };

  async function through(bytes, stream) {
    const res = new Response(new Blob([bytes]).stream().pipeThrough(stream));
    return new Uint8Array(await res.arrayBuffer());
  }
  function detectFormat(b) {
    if (b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
    if (b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd) return 'zstd';
    if ((b[0] & 0x0f) === 8 && (b[0] >> 4) <= 7 && ((b[0] << 8) | b[1]) % 31 === 0) return 'zlib';
    return 'raw';
  }
  async function compress(bytes, fmt) {
    if (typeof CompressionStream === 'undefined') throw new Error('이 브라우저는 압축 기능(Compression Streams)을 지원하지 않습니다.');
    return through(bytes, new CompressionStream(FORMATS[fmt]));
  }
  async function decompress(bytes, fmt) {
    if (typeof DecompressionStream === 'undefined') throw new Error('이 브라우저는 압축 해제 기능(Compression Streams)을 지원하지 않습니다.');
    const f = fmt === 'auto' ? detectFormat(bytes) : fmt;
    if (!supported(FORMATS[f])) throw new Error(`이 브라우저는 ${f} 해제를 지원하지 않습니다.`);
    try { return { out: await through(bytes, new DecompressionStream(FORMATS[f])), fmt: f }; }
    catch {
      throw new Error(`${f === 'raw' ? 'Raw DEFLATE' : f} 데이터로 해제할 수 없습니다. 형식을 바꾸거나, 입력 형식(Base64/Hex)이 맞는지 확인하세요.`);
    }
  }

  /* ---------- 헤더 분석 ---------- */
  const GZIP_OS = { 0: 'FAT (Windows)', 3: 'Unix', 7: 'Macintosh', 10: 'NTFS', 11: 'NTFS', 255: '알 수 없음' };
  function gzipInfo(b) {
    const flg = b[3];
    const mtime = b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24);
    const lines = ['형식      Gzip (RFC 1952)', `압축 방식 ${b[2] === 8 ? 'DEFLATE' : `알 수 없음 (${b[2]})`}`];
    if (mtime) lines.push(`수정 시각 ${new Date(mtime * 1000).toISOString()}`);
    lines.push(`운영체제  ${GZIP_OS[b[9]] || b[9]}`, `압축 수준 ${b[8] === 2 ? '최대 압축' : b[8] === 4 ? '최고 속도' : '기본'}`);
    let p = 10;
    if (flg & 4) p += 2 + (b[p] | (b[p + 1] << 8));
    if (flg & 8) { const e = b.indexOf(0, p); lines.push(`원본 파일명 ${latin1(b.subarray(p, e))}`); p = e + 1; }
    if (flg & 16) { const e = b.indexOf(0, p); lines.push(`주석      ${latin1(b.subarray(p, e))}`); }
    if (b.length >= 18) {
      const n = b.length;
      lines.push(`원본 크기 ${((b[n - 4] | (b[n - 3] << 8) | (b[n - 2] << 16) | (b[n - 1] << 24)) >>> 0).toLocaleString()} B (트레일러 기준, 4 GB 미만일 때 정확)`);
    }
    return lines;
  }
  function zlibInfo(b) {
    const window = 1 << ((b[0] >> 4) + 8);
    const level = ['최고 속도', '빠름', '기본', '최대 압축'][b[1] >> 6];
    return ['형식      Zlib (RFC 1950)', `윈도 크기 ${window.toLocaleString()} B`, `압축 수준 ${level}`, `사전 사용 ${b[1] & 0x20 ? '예 (사전 없이 해제 불가)' : '아니오'}`];
  }

  /* ---------- ZIP ---------- */
  const u16 = (b, o) => b[o] | (b[o + 1] << 8);
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const ZIP_METHOD = { 0: '저장', 8: 'Deflate', 9: 'Deflate64', 12: 'Bzip2', 14: 'LZMA', 93: 'Zstd', 99: 'AES 암호화' };
  function zipEntries(b) {
    let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (u32(b, i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error('ZIP 중앙 디렉터리(EOCD)를 찾지 못했습니다. ZIP 파일 전체를 열어 주세요.');
    const count = u16(b, eocd + 10);
    let p = u32(b, eocd + 16);
    const entries = [];
    for (let i = 0; i < count; i++) {
      if (u32(b, p) !== 0x02014b50) throw new Error('ZIP 중앙 디렉터리가 손상되었습니다.');
      const nameLen = u16(b, p + 28), extraLen = u16(b, p + 30), commentLen = u16(b, p + 32);
      const flags = u16(b, p + 8);
      entries.push({
        name: (flags & 0x800 ? DL.utf8Decode : latin1)(b.subarray(p + 46, p + 46 + nameLen)),
        method: u16(b, p + 10), encrypted: !!(flags & 1), csize: u32(b, p + 20), size: u32(b, p + 24),
        crc: u32(b, p + 16), offset: u32(b, p + 42),
      });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }
  async function zipExtract(b, e) {
    if (e.encrypted) throw new Error(`"${e.name}"은(는) 암호가 걸려 있어 추출할 수 없습니다.`);
    const p = e.offset;
    if (u32(b, p) !== 0x04034b50) throw new Error('로컬 파일 헤더를 찾을 수 없습니다.');
    const start = p + 30 + u16(b, p + 26) + u16(b, p + 28);
    const data = b.subarray(start, start + e.csize);
    if (e.method === 0) return data;
    if (e.method === 8) return (await decompress(data, 'raw')).out;
    throw new Error(`압축 방식 "${ZIP_METHOD[e.method] || e.method}"은(는) 지원하지 않습니다.`);
  }

  /* ---------- LZ4 (프레임 / 블록) ---------- */
  class Grow {
    constructor(n = 1024) { this.buf = new Uint8Array(n); this.len = 0; }
    ensure(n) { if (this.len + n > this.buf.length) { const b = new Uint8Array(Math.max(this.buf.length * 2, this.len + n)); b.set(this.buf.subarray(0, this.len)); this.buf = b; } }
    push(arr) { this.ensure(arr.length); this.buf.set(arr, this.len); this.len += arr.length; }
    result() { return this.buf.slice(0, this.len); }
  }
  const LIMIT = 256 * 1024 * 1024;
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

  Object.assign(DL.fn, { compress, decompress, detectFormat, lz4Decompress, xzDecompress, lzmaAlone, bzip2Decompress });

  const brotliTool = (
      {
        id: 'brotli', name: 'Brotli · Zstd 해제', short: '브라우저가 지원하는 경우',
        desc: '웹 서버 응답에 쓰이는 Brotli와 고성능 압축 Zstandard를 해제합니다. 브라우저 내장 기능을 사용하므로 브라우저가 지원하지 않으면 안내 메시지가 나옵니다.',
        fileInput: true, slow: true,
        modes: [{ id: 'decompress', label: '압축 해제', inLabel: '압축 데이터', outLabel: '원본' }],
        options: [
          { id: 'fmt', label: '형식', type: 'select', default: 'brotli', choices: [['brotli', 'Brotli'], ['zstd', 'Zstandard']] },
          fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']),
          fmtOption('outFmt', '출력 형식', 'text', ['text', 'hex', 'base64']),
        ],
        decompress: async (s, o) => {
          const { out } = await decompress(readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt), o.fmt);
          return o.outFmt === 'text' ? out : formatBytes(out, o.outFmt);
        },
      }
  );
  const nativeFormats = ['brotli', 'zstd'].filter((f) => typeof DecompressionStream !== 'undefined' && supported(f));

  const cat = DL.addCategory({
    id: 'compress',
    name: '압축·데이터 복원',
    desc: '암호문처럼 보이는 데이터가 실제로는 압축된 경우가 많습니다 — Gzip·Zlib·Deflate 압축과 해제, ZIP 내용 확인',
    color: 'yellow',
    tools: [
      {
        id: 'deflate', name: 'Gzip · Zlib · Deflate', short: '압축 / 해제 · 형식 자동 판별',
        desc: 'HTTP 응답, PDF 스트림, 웹 토큰 등에 쓰이는 DEFLATE 계열 압축입니다. 해제 시 "자동"을 고르면 Gzip(1f 8b)·Zlib(78 xx)·Raw를 헤더로 판별합니다. 압축 결과는 바이너리라서 Base64나 Hex로 표시합니다.',
        fileInput: true, slow: true,
        modes: [
          { id: 'decompress', label: '압축 해제', inLabel: '압축 데이터', outLabel: '원본', placeholder: 'Base64 또는 16진수 (예: H4sIA…)' },
          { id: 'compress', label: '압축', inLabel: '원본', outLabel: '압축 데이터' },
        ],
        options: [
          { id: 'fmt', label: '형식', type: 'select', default: 'auto', mode: 'decompress', choices: [['auto', '자동'], ['gzip', 'Gzip'], ['zlib', 'Zlib'], ['raw', 'Raw DEFLATE']] },
          { id: 'cfmt', label: '형식', type: 'select', default: 'gzip', mode: 'compress', choices: [['gzip', 'Gzip'], ['zlib', 'Zlib'], ['raw', 'Raw DEFLATE']] },
          { ...fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']), mode: 'decompress' },
          { ...fmtOption('outFmt', '출력 형식', 'text', ['text', 'hex', 'base64']), mode: 'decompress' },
          { ...fmtOption('srcFmt', '입력 형식', 'text', ['text', 'hex', 'base64']), mode: 'compress' },
          { ...fmtOption('zFmt', '출력 형식', 'base64', ['base64', 'hex']), mode: 'compress' },
        ],
        decompress: async (s, o) => {
          const { out } = await decompress(readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt), o.fmt);
          return o.outFmt === 'text' ? out : formatBytes(out, o.outFmt);
        },
        compress: async (s, o) => {
          const src = readBytes(s, o.srcFmt);
          const out = await compress(src, o.cfmt);
          return formatBytes(out, o.zFmt);
        },
      },
      {
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
      },
      {
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
      },
      {
        id: 'identify', name: '압축 형식 식별', short: '헤더 분석 · 원본 파일명',
        desc: '압축 데이터의 헤더를 해석해 형식, 압축 수준, 원본 파일명, 수정 시각, 원본 크기 등을 보여줍니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '분석', inLabel: '압축 데이터', outLabel: '헤더 정보' }],
        options: [fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex'])],
        run: (s, o) => {
          const b = readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt);
          if (b[0] === 0x1f && b[1] === 0x8b) return gzipInfo(b).join('\n');
          if (detectFormat(b) === 'zlib') return zlibInfo(b).join('\n');
          const magic = DL.fn.identifyMagic ? DL.fn.identifyMagic(b) : [];
          if (magic.length) return `${magic.map((m) => m.name).join(', ')}\n\n처음 16 B: ${toHex(b.subarray(0, 16), false, ' ')}`;
          return `알려진 압축 헤더가 없습니다. 헤더 없는 Raw DEFLATE일 수 있습니다 — "Gzip · Zlib · Deflate"에서 Raw로 해제해 보세요.\n\n처음 16 B: ${toHex(b.subarray(0, 16), false, ' ')}`;
        },
      },
      {
        id: 'zip', name: 'ZIP 목록 · 추출', short: '파일 목록 보기 · 개별 추출',
        desc: 'ZIP 파일(docx·xlsx·apk·jar 포함) 안의 파일 목록과 크기, 압축 방식, 암호화 여부를 보여주고, 번호를 지정하면 해당 파일을 추출합니다.',
        fileInput: true, slow: true,
        modes: [{ id: 'run', label: '열기', inLabel: 'ZIP 데이터', outLabel: '목록 / 내용', placeholder: '파일 열기를 누르거나 Base64를 붙여 넣으세요' }],
        options: [
          fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']),
          { id: 'entry', label: '추출할 번호 (0 = 목록)', type: 'number', default: 0, min: 0 },
        ],
        run: async (s, o) => {
          const b = readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt);
          const entries = zipEntries(b);
          const n = Number(o.entry) || 0;
          if (n > 0) {
            const e = entries[n - 1];
            if (!e) throw new Error(`${n}번 항목이 없습니다. (총 ${entries.length}개)`);
            return zipExtract(b, e);
          }
          const rows = entries.map((e, i) => `${String(i + 1).padStart(3)}  ${e.size.toLocaleString().padStart(12)} B  ${(ZIP_METHOD[e.method] || e.method).toString().padEnd(8)}${e.encrypted ? ' 🔒' : '   '}  ${e.name}`);
          return `${entries.length}개 항목 · 번호를 옵션에 넣으면 추출합니다\n\n  #         크기      방식\n${rows.join('\n')}`;
        },
      },
    ],
    planned: [],
  });
  // Brotli·Zstd 해제는 브라우저 내장 기능이 있을 때만 노출하고, 없으면 준비 중으로 표시한다.
  if (nativeFormats.length) {
    brotliTool.options[0].choices = brotliTool.options[0].choices.filter(([v]) => nativeFormats.includes(v));
    brotliTool.options[0].default = nativeFormats[0];
    cat.tools.splice(1, 0, brotliTool);
  } else cat.planned.push(['Brotli · Zstd 해제', '이 브라우저는 아직 내장 지원하지 않음']);
})(globalThis.DecryptLab);
