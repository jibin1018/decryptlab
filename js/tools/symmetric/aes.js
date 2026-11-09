/* 대칭키 암호 › AES */
(function (DL) {
  'use strict';
  const K = DL.kits.symmetric;
  DL.addTool('symmetric', K.blockTool({
    id: 'aes', cipher: K.AES, name: 'AES', short: '128/192/256 · CBC·GCM·CTR 등',
    desc: '현대 표준 블록 암호입니다. 키 길이(16/24/32 B)로 AES-128/192/256이 결정됩니다. GCM은 암호문 끝에 16 B 인증 태그를 붙입니다. 결과가 깨지면 모드·IV·패딩·키 형식을 차례로 확인하세요.',
    defaultKey: '000102030405060708090a0b0c0d0e0f', modes: K.ALL_MODES,
  }));
})(globalThis.DecryptLab);
