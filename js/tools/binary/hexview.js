/* 바이너리 분석 › 헥스 뷰어 */
(function (DL) {
  'use strict';
  const { readBytes, hexdump, IN } = DL.kits.binary;

  DL.addTool('binary', {
    id: 'hexview', name: '헥스 뷰어', short: '오프셋 · 16진수 · ASCII',
    desc: '바이트를 오프셋, 16진수, ASCII로 나란히 보여줍니다. "파일 열기"로 실제 파일을 열 수 있으며, 한 번에 최대 64 KB를 표시합니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '보기', inLabel: '데이터', outLabel: '헥스 덤프' }],
    options: [
      IN('text'),
      { id: 'width', label: '한 줄 바이트', type: 'select', default: '16', choices: [['8', '8'], ['16', '16'], ['32', '32']] },
      { id: 'start', label: '시작 오프셋 (16진)', type: 'text', default: '0' },
    ],
    run: (s, o) => {
      const bytes = readBytes(s, o.inFmt);
      const start = parseInt(o.start || '0', 16);
      if (!Number.isFinite(start) || start < 0) throw new Error('시작 오프셋은 16진수여야 합니다.');
      if (start >= bytes.length && bytes.length) throw new Error(`시작 오프셋이 데이터 크기(0x${bytes.length.toString(16)})를 넘습니다.`);
      return hexdump(bytes, { width: Number(o.width), start });
    },
  });
})(globalThis.DecryptLab);
