/* 대칭키 암호 › ARIA */
(function (DL) {
  'use strict';
  const K = DL.kits.symmetric;
  DL.addTool('symmetric', K.blockTool({
    id: 'aria', cipher: K.ARIA, name: 'ARIA', short: '국가 표준 · KS X 1213',
    desc: '국가보안기술연구소가 개발한 한국 표준 블록 암호로, 공공기관 시스템에서 널리 쓰입니다. AES와 같은 128비트 블록, 128/192/256비트 키를 사용합니다.',
    defaultKey: '000102030405060708090a0b0c0d0e0f', modes: K.ALL_MODES,
  }));
})(globalThis.DecryptLab);
