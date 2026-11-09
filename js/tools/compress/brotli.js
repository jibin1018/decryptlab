/* 압축·데이터 복원 › Brotli · Zstd 해제 (브라우저가 지원할 때만 노출)
 * deflate.js 바로 다음에 로드되어 목록에서 두 번째에 온다. */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, supported, decompress } = DL.kits.compress;

  const nativeFormats = ['brotli', 'zstd'].filter((f) => typeof DecompressionStream !== 'undefined' && supported(f));
  if (!nativeFormats.length) {
    const cat = DL.CATEGORIES.find((c) => c.id === 'compress');
    cat.planned.push(['Brotli · Zstd 해제', '이 브라우저는 아직 내장 지원하지 않음']);
    return;
  }

  DL.addTool('compress', {
    id: 'brotli', name: 'Brotli · Zstd 해제', short: '브라우저가 지원하는 경우',
    desc: '웹 서버 응답에 쓰이는 Brotli와 고성능 압축 Zstandard를 해제합니다. 브라우저 내장 기능을 사용하므로 브라우저가 지원하지 않으면 안내 메시지가 나옵니다.',
    fileInput: true, slow: true,
    modes: [{ id: 'decompress', label: '압축 해제', inLabel: '압축 데이터', outLabel: '원본' }],
    options: [
      { id: 'fmt', label: '형식', type: 'select', default: nativeFormats[0], choices: [['brotli', 'Brotli'], ['zstd', 'Zstandard']].filter(([v]) => nativeFormats.includes(v)) },
      fmtOption('inFmt', '입력 형식', 'base64', ['base64', 'hex']),
      fmtOption('outFmt', '출력 형식', 'text', ['text', 'hex', 'base64']),
    ],
    decompress: async (s, o) => {
      const { out } = await decompress(readBytes(typeof s === 'string' ? s.trim() : s, o.inFmt), o.fmt);
      return o.outFmt === 'text' ? out : formatBytes(out, o.outFmt);
    },
  });
})(globalThis.DecryptLab);
