/* 고전 암호 › 열 전치 암호 */
(function (DL) {
  'use strict';
  const { columnarEnc, columnarDec, ENC_DEC } = DL.kits.classic;

  DL.addTool('classic', {
    id: 'columnar', name: '열 전치 암호', short: '키워드 순서로 열 읽기',
    desc: '평문을 키 길이만큼의 행으로 나눠 적고, 키 글자의 알파벳 순서대로 열을 읽습니다. 공백도 한 글자로 취급합니다.',
    modes: ENC_DEC,
    options: [{ id: 'key', label: '키', type: 'text', default: 'ZEBRAS' }, { id: 'strip', label: '공백 제거', type: 'checkbox', default: true, mode: 'encode' }],
    encode: (s, o) => columnarEnc(o.strip ? s.replace(/\s/g, '') : s, o.key),
    decode: (s, o) => columnarDec(s, o.key),
  });
})(globalThis.DecryptLab);
