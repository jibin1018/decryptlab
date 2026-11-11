/* 자동 분석 — 카테고리 셸 + 공유 헬퍼 (DL.kits.auto)
 * 각 도구 파일이 자신의 핵심 함수를 DL.kits.auto에 등록하고,
 * 종합 리포트(report.js)는 실행 시점에 그 함수들을 참조한다. */
(function (DL) {
  'use strict';
  const { utf8, utf8Decode, b64decode, b64encode, fromHex, printableScore, textScore, toHex, entropy, fn } = DL;

  DL.kits.auto = { utf8, utf8Decode, b64decode, b64encode, fromHex, printableScore, textScore, toHex, entropy, fn };

  DL.addCategory({
    id: 'auto',
    name: '자동 분석',
    desc: '정체 모를 값을 자동으로 풀고 유형을 추정합니다',
    color: 'lime',
    tools: [],
    planned: [],
  });
})(globalThis.DecryptLab);
