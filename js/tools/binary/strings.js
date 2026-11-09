/* 바이너리 분석 › 문자열 추출 */
(function (DL) {
  'use strict';
  const { readBytes, latin1, IN } = DL.kits.binary;

  function extractStrings(bytes, { min = 4, enc = 'both', limit = 5000 } = {}) {
    const found = [];
    const isP = (b) => b >= 32 && b < 127;
    if (enc !== 'utf16') {
      let start = -1;
      for (let i = 0; i <= bytes.length; i++) {
        if (i < bytes.length && isP(bytes[i])) { if (start < 0) start = i; }
        else if (start >= 0) {
          if (i - start >= min) found.push([start, 'A', latin1(bytes.subarray(start, i))]);
          start = -1;
        }
      }
    }
    if (enc !== 'ascii') {
      for (const phase of [0, 1]) {
        let start = -1, s = '';
        for (let i = phase; i + 1 <= bytes.length; i += 2) {
          if (i + 1 < bytes.length && isP(bytes[i]) && bytes[i + 1] === 0) { if (start < 0) start = i; s += String.fromCharCode(bytes[i]); }
          else { if (start >= 0 && s.length >= min) found.push([start, 'W', s]); start = -1; s = ''; }
        }
      }
    }
    found.sort((a, b) => a[0] - b[0]);
    const out = found.slice(0, limit).map(([off, t, s]) => `${off.toString(16).padStart(8, '0')}  ${t}  ${s}`);
    if (!out.length) return `길이 ${min} 이상의 문자열을 찾지 못했습니다.`;
    return `${found.length.toLocaleString()}개 발견 (A = ASCII, W = UTF-16LE)${found.length > limit ? ` · 처음 ${limit}개만 표시` : ''}\n\n${out.join('\n')}`;
  }
  DL.fn.extractStrings = extractStrings;

  DL.addTool('binary', {
    id: 'strings', name: '문자열 추출', short: 'ASCII · UTF-16 strings',
    desc: '바이너리 안에 들어 있는 읽을 수 있는 문자열을 오프셋과 함께 뽑아냅니다(유닉스 strings 명령과 같음). 실행 파일에서 URL, 경로, 메시지를 찾을 때 씁니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '추출', inLabel: '데이터', outLabel: '문자열 목록' }],
    options: [
      IN('hex'),
      { id: 'min', label: '최소 길이', type: 'number', default: 4, min: 2, max: 100 },
      { id: 'enc', label: '종류', type: 'select', default: 'both', choices: [['both', 'ASCII + UTF-16LE'], ['ascii', 'ASCII'], ['utf16', 'UTF-16LE']] },
    ],
    run: (s, o) => extractStrings(readBytes(s, o.inFmt), { min: Math.max(2, Number(o.min) || 4), enc: o.enc }),
  });
})(globalThis.DecryptLab);
