/* 바이너리 분석 › XOR 전수 조사 */
(function (DL) {
  'use strict';
  const { readBytes, latin1, asciiChar, IN } = DL.kits.binary;

  const EN = 'etaoin shrdlu';
  function englishScore(bytes) {
    let score = 0;
    for (const b of bytes) {
      if (b === 32) score += 3;
      else if ((b >= 97 && b <= 122) || (b >= 65 && b <= 90)) score += EN.includes(String.fromCharCode(b | 32)) ? 2 : 1;
      else if (b >= 48 && b <= 57) score += 0.5;
      else if (b === 10 || b === 13 || b === 9 || (b >= 33 && b < 127)) score += 0;
      else score -= 6;
    }
    return score / bytes.length;
  }
  function xorBrute(bytes, { crib = '', top = 10 } = {}) {
    if (!bytes.length) throw new Error('분석할 데이터가 없습니다.');
    const cribLow = crib.toLowerCase();
    const results = [];
    for (let k = 0; k < 256; k++) {
      const out = bytes.map((b) => b ^ k);
      const text = latin1(out);
      if (crib && !text.toLowerCase().includes(cribLow)) continue;
      results.push({ k, score: englishScore(out), text });
    }
    if (!results.length) return `"${crib}"를 포함하는 단일 바이트 XOR 결과가 없습니다. 키가 여러 바이트일 수 있습니다.`;
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, Number(top) || 10).map(({ k, score, text }, i) => {
      const preview = text.replace(/[^\x20-\x7e\n]/g, '·');
      return `[${i + 1}] 키 0x${k.toString(16).padStart(2, '0')} ('${asciiChar(k)}')  점수 ${score.toFixed(2)}\n${preview.length > 400 ? preview.slice(0, 400) + ' …' : preview}`;
    }).join('\n\n');
  }
  Object.assign(DL.fn, { xorBrute, englishScore });

  DL.addTool('binary', {
    id: 'xorbrute', name: 'XOR 전수 조사', short: '단일 바이트 키 자동 탐색',
    desc: '256가지 단일 바이트 키로 모두 XOR한 뒤, 영어 문장에 가까운 결과부터 보여줍니다. "포함 문자열"에 flag 같은 알려진 평문을 넣으면 후보를 좁힐 수 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '전수 조사', inLabel: '암호문', outLabel: '후보 (점수순)', placeholder: '16진수 바이트 (예: 1b37373331363f78…)' }],
    options: [
      IN('hex'),
      { id: 'crib', label: '포함 문자열', type: 'text', default: '' },
      { id: 'top', label: '후보 수', type: 'number', default: 10, min: 1, max: 256 },
    ],
    run: (s, o) => xorBrute(readBytes(s, o.inFmt), o),
  });
})(globalThis.DecryptLab);
