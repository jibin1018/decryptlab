/* 바이너리 분석 › 파일 시그니처 판별 */
(function (DL) {
  'use strict';
  const { utf8Decode, toHex, readBytes, printableScore, identifyMagic, IN } = DL.kits.binary;

  DL.addTool('binary', {
    id: 'magic', name: '파일 시그니처 판별', short: '매직 바이트로 형식 추정',
    desc: '파일 앞부분의 매직 바이트로 실제 형식을 판별합니다. 확장자를 바꿔 위장한 파일이나, 디코딩 결과가 어떤 파일인지 확인할 때 유용합니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '판별', inLabel: '데이터', outLabel: '판별 결과', placeholder: '16진수 바이트 또는 파일 열기' }],
    options: [IN('hex')],
    run: (s, o) => {
      const bytes = readBytes(s, o.inFmt);
      const hits = identifyMagic(bytes);
      const head = `처음 16 B: ${toHex(bytes.subarray(0, 16), false, ' ')}`;
      if (hits.length) return `${hits.map((h) => `✓ ${h.name}  (.${h.ext})${h.note ? `  — ${h.note}` : ''}`).join('\n')}\n\n${head}`;
      let text = null;
      try { text = utf8Decode(bytes, true); } catch { /* 바이너리 */ }
      if (text !== null && printableScore(text) > 0.95) return `알려진 시그니처는 없지만 UTF-8 텍스트로 보입니다.\n\n${head}`;
      return `알려진 시그니처와 일치하지 않습니다. 암호화되었거나, 압축되었거나, 헤더가 없는 데이터일 수 있습니다. "엔트로피 분석"으로 확인해 보세요.\n\n${head}`;
    },
  });
})(globalThis.DecryptLab);
