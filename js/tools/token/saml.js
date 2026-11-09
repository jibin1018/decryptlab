/* 웹 토큰·인증서 › SAML 디코더 */
(function (DL) {
  'use strict';
  const { samlDecode } = DL.kits.token;

  DL.addTool('token', {
    id: 'saml', name: 'SAML 디코더', short: 'SAMLRequest · SAMLResponse',
    desc: 'SSO에 쓰이는 SAML 메시지를 디코딩합니다. URL 전체, 파라미터 값, Base64만 넣어도 되며 HTTP-Redirect 바인딩의 DEFLATE 압축도 자동으로 풉니다.',
    slow: true,
    modes: [{ id: 'run', label: '디코딩', inLabel: 'SAML 메시지', outLabel: 'XML' }],
    run: (s) => samlDecode(s),
  });
})(globalThis.DecryptLab);
