/* 고전 암호 › 모스 부호 */
(function (DL) {
  'use strict';
  const MORSE = {
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
    K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
    U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
    0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.',
  };
  const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
  function morseEncode(s) {
    return s.toUpperCase().trim().split(/\s+/).map((w) => Array.from(w).map((c) => {
      if (!MORSE[c]) throw new Error(`모스 부호로 표현할 수 없는 문자: "${c}"`);
      return MORSE[c];
    }).join(' ')).join(' / ');
  }
  function morseDecode(s) {
    const norm = s.replace(/[·•]/g, '.').replace(/[_−–—]/g, '-').trim();
    return norm.split(/\s*[\/|]\s*|\s{3,}/).map((w) => w.trim().split(/\s+/).filter(Boolean).map((code) => {
      if (!MORSE_REV[code]) throw new Error(`알 수 없는 모스 부호: "${code}"`);
      return MORSE_REV[code];
    }).join('')).join(' ');
  }
  DL.fn.morseDecode = morseDecode;

  DL.addTool('classic', {
    id: 'morse', name: '모스 부호', short: '. - / 표기',
    desc: '문자는 공백으로, 단어는 / 로 구분합니다. 디코딩 시 · 와 _ 같은 변형 기호도 인식합니다.',
    encode: (s) => morseEncode(s),
    decode: (s) => morseDecode(s),
  });
})(globalThis.DecryptLab);
