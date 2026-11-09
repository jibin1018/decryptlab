/* 대칭키 암호 › SEED */
(function (DL) {
  'use strict';
  const K = DL.kits.symmetric;
  DL.addTool('symmetric', K.blockTool({
    id: 'seed', cipher: K.SEED, name: 'SEED', short: 'KISA 표준 · 128비트',
    desc: '한국인터넷진흥원(KISA)이 개발한 128비트 블록 암호입니다. 과거 국내 인터넷 뱅킹과 공인인증서에서 사용되었습니다. 키는 16 B만 사용합니다.',
    defaultKey: '000102030405060708090a0b0c0d0e0f', modes: K.ALL_MODES,
  }));
})(globalThis.DecryptLab);
