/* 압축·데이터 복원 › ZIP 목록 · 추출 */
(function (DL) {
  'use strict';
  const { readBytes, fmtOption, latin1, decompress } = DL.kits.compress;

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

  DL.addTool('compress', {
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
  });
})(globalThis.DecryptLab);
