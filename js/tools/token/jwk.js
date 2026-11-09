/* 웹 토큰·인증서 › JWK ↔ PEM */
(function (DL) {
  'use strict';
  const { jwkToPem, pemToJwk } = DL.kits.token;

  DL.addTool('token', {
    id: 'jwk', name: 'JWK ↔ PEM', short: 'JSON Web Key · JWKS · 지문',
    desc: 'JWK/JWKS(키 세트)를 PEM으로, PEM을 JWK로 바꿉니다. RFC 7638 지문(thumbprint)도 계산해 kid 확인에 쓸 수 있습니다.',
    slow: true,
    modes: [
      { id: 'decode', label: 'JWK → PEM', inLabel: 'JWK / JWKS', outLabel: 'PEM', placeholder: '{"kty":"EC","crv":"P-256","x":"…","y":"…"}' },
      { id: 'encode', label: 'PEM → JWK', inLabel: 'PEM', outLabel: 'JWK', placeholder: '-----BEGIN PUBLIC KEY----- …' },
    ],
    decode: (s) => jwkToPem(s),
    encode: (s) => pemToJwk(s),
  });
})(globalThis.DecryptLab);
