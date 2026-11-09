/* 웹 토큰·인증서 › JWT 디코더 */
(function (DL) {
  'use strict';
  const { jwtDecode } = DL.kits.token;

  DL.addTool('token', {
    id: 'jwt', name: 'JWT 디코더', short: 'Header · Payload · 만료 확인',
    desc: 'JSON Web Token의 헤더와 페이로드를 풀어 보여주고, exp/iat 시간과 alg:none 같은 위험 신호를 표시합니다. 서명 검증은 "JWT 서명 검증·생성"에서 할 수 있습니다.',
    modes: [{ id: 'run', label: '디코딩', inLabel: 'JWT', outLabel: '디코딩 결과', placeholder: 'eyJhbGciOi…' }],
    run: (s) => (s.trim() ? jwtDecode(s) : ''),
  });
})(globalThis.DecryptLab);
