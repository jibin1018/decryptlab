/* 압축·데이터 복원 — 카테고리 셸 + 공유 헬퍼 (DL.kits.compress)
 * 브라우저 내장 Compression Streams를 사용한다. */
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
  Object.assign(DL.fn, { compress, decompress, detectFormat });

  DL.kits.compress = { readBytes, formatBytes, fmtOption, toHex, latin1, FORMATS, supported, detectFormat, compress, decompress };

  DL.addCategory({
    id: 'compress',
    name: '압축·데이터 복원',
    desc: 'Gzip·XZ·LZ4·ZIP 압축 해제와 식별',
    color: 'yellow',
    tools: [],
    planned: [],
  });
})(globalThis.DecryptLab);
