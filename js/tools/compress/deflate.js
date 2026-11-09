/* 압축·데이터 복원 › Gzip · Zlib · Deflate */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, compress, decompress } = DL.kits.compress;

  DL.addTool('compress', {
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
  });
})(globalThis.DecryptLab);
