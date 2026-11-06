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

  Object.assign(DL.fn, { compress, decompress, detectFormat, lz4Decompress });

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
  cat.planned.push(['LZMA · XZ · Bzip2', '추가 압축 형식 해제']);
})(globalThis.DecryptLab);
