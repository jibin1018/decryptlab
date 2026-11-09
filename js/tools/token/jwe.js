/* 웹 토큰·인증서 › JWE 복호화 */
(function (DL) {
  'use strict';
  const { jweDecrypt } = DL.kits.token;

  DL.addTool('token', {
    id: 'jwe', name: 'JWE 복호화', short: '암호화된 JWT · RSA · AES-KW · ECDH-ES · PBES2',
    desc: '점이 4개인 암호화된 토큰(JWE)을 복호화합니다. 키 관리 방식 dir·RSA-OAEP(-256)·A128/192/256KW·ECDH-ES(+AES-KW)·PBES2와 콘텐츠 암호화 A*GCM·A*CBC-HS*를 지원하며, 키 없이 넣으면 헤더만 보여줍니다. ECDH-ES는 P-256/384/521·X25519 수신자 개인키를, PBES2는 비밀번호를 넣으세요.',
    slow: true,
    modes: [{ id: 'run', label: '복호화', inLabel: 'JWE', outLabel: '복호화 결과', placeholder: 'eyJhbGciOiJSU0EtT0FFUC0yNTYi… (5개 부분)' }],
    options: [
      { id: 'key', label: '키 / 비밀번호', type: 'textarea', default: '', wide: true, placeholder: 'RSA·ECDH-ES: 개인키 PEM/JWK · dir/AES-KW: 대칭키 또는 {"kty":"oct","k":"…"} · PBES2: 비밀번호' },
      { id: 'keyFmt', label: '대칭키 형식', type: 'select', default: 'base64', choices: [['base64', 'Base64 / Base64URL'], ['hex', '16진수'], ['text', '텍스트']] },
    ],
    run: (s, o) => jweDecrypt(s, o),
  });
})(globalThis.DecryptLab);
