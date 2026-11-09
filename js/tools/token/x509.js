/* 웹 토큰·인증서 › X.509 인증서 */
(function (DL) {
  'use strict';
  const { fmtOption, x509Report, readDer } = DL.kits.token;

  DL.addTool('token', {
    id: 'x509', name: 'X.509 인증서', short: '주체·발급자·유효기간·SAN',
    desc: 'TLS 인증서를 사람이 읽기 쉽게 요약합니다. 주체·발급자, 유효 기간과 만료 여부, 공개키, SAN(도메인 목록), 용도, 지문을 보여줍니다.',
    fileInput: true, slow: true,
    modes: [{ id: 'run', label: '분석', inLabel: '인증서', outLabel: '인증서 정보', placeholder: '-----BEGIN CERTIFICATE----- …' }],
    options: [fmtOption('inFmt', 'DER 입력 형식', 'base64', ['base64', 'hex'])],
    run: (s, o) => x509Report(readDer(s, o.inFmt).der),
  });
})(globalThis.DecryptLab);
