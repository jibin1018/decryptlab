/* 웹 토큰·인증서 › JWT 서명 검증·생성 */
(function (DL) {
  'use strict';
  const { jwtVerify, jwtSign, JWT_ALGS, KEY_TEXTAREA } = DL.kits.token;

  DL.addTool('token', {
    id: 'jwtverify', name: 'JWT 서명 검증·생성', short: 'HS · RS · PS · ES · EdDSA',
    desc: '비밀키나 공개키로 JWT 서명을 검증하고, 페이로드 JSON으로 새 토큰을 만듭니다. 알고리즘은 검증 시 토큰 헤더를 따릅니다.',
    slow: true,
    modes: [
      { id: 'verify', label: '검증', inLabel: 'JWT', outLabel: '검증 결과' },
      { id: 'sign', label: '생성', inLabel: '페이로드 (JSON)', outLabel: 'JWT', placeholder: '{"sub":"1234","name":"홍길동","iat":1700000000}' },
    ],
    options: [
      { id: 'alg', label: '알고리즘', type: 'select', default: 'HS256', mode: 'sign', choices: Object.keys(JWT_ALGS).map((k) => [k, k]) },
      { ...KEY_TEXTAREA, default: 'your-256-bit-secret' },
      { id: 'secretFmt', label: 'HMAC 키 형식', type: 'select', default: 'text', choices: [['text', '텍스트'], ['base64', 'Base64 / Base64URL']] },
    ],
    verify: (s, o) => jwtVerify(s, o),
    sign: (s, o) => jwtSign(s, o),
  });
})(globalThis.DecryptLab);
