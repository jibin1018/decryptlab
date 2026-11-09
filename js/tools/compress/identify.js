/* 압축·데이터 복원 › 압축 형식 식별 */
(function (DL) {
  'use strict';
  const { readBytes, fmtOption, toHex, latin1, detectFormat } = DL.kits.compress;

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

  DL.addTool('compress', {
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
  });
})(globalThis.DecryptLab);
