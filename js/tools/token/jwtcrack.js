/* 웹 토큰·인증서 › JWT 서명키 찾기 (본인 소유·실습용 HS* 토큰 전용) */
(function (DL) {
  'use strict';
  const { jwtCrack } = DL.kits.token;

  DL.addTool('token', {
    id: 'jwtcrack', name: 'JWT 서명키 찾기', short: 'HS256/384/512 비밀키 사전 공격',
    desc: '본인 소유·실습용 HS* 토큰의 잊어버린 비밀키를 찾습니다. 내장 약한 키 목록과 변형, 직접 넣은 단어 목록, 선택적 짧은 무차별 대입으로 서명이 맞는 키를 탐색합니다. 모든 계산은 브라우저 안에서만 이루어지며, 강한 무작위 키는 복구되지 않습니다. 남의 토큰 키를 알아내는 용도로 쓰지 마세요.',
    slow: true,
    modes: [{ id: 'run', label: '키 찾기', inLabel: 'JWT (HS256/384/512)', outLabel: '결과', placeholder: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.…' }],
    options: [
      { id: 'useCommon', label: '내장 약한 키 목록 사용', type: 'checkbox', default: true },
      { id: 'mangle', label: '변형 추가 (대소문자·숫자·기호 붙이기)', type: 'checkbox', default: true },
      { id: 'wordlist', label: '단어 목록 (한 줄에 하나)', type: 'textarea', default: '', wide: true, placeholder: '후보 키를 한 줄에 하나씩 붙여 넣으세요 (선택)' },
      { id: 'brute', label: '짧은 무차별 대입도 시도', type: 'checkbox', default: false },
      { id: 'charset', label: '문자셋', type: 'select', default: 'lower', when: (o) => o.brute, choices: [['lower', '소문자 (a–z)'], ['digits', '숫자 (0–9)'], ['alnum', '소문자+숫자'], ['loweralpha', '대소문자']] },
      { id: 'maxLen', label: '최대 길이', type: 'number', default: 4, min: 1, max: 6, when: (o) => o.brute },
    ],
    run: (s, o) => (s.trim() ? jwtCrack(s, o) : ''),
  });
})(globalThis.DecryptLab);
