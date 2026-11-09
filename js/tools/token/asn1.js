/* 웹 토큰·인증서 › PEM · DER · ASN.1 뷰어 */
(function (DL) {
  'use strict';
  const { asn1Parse, fmtOption, asn1Tree, readDer } = DL.kits.token;

  DL.addTool('token', {
    id: 'asn1', name: 'PEM · DER · ASN.1 뷰어', short: '키·인증서 구조 트리',
    desc: 'PEM이나 DER을 ASN.1 구조 트리로 풀어 보여줍니다. 각 줄 앞의 숫자는 바이트 오프셋이며, OID는 이름으로 표시합니다. 인증서, 키, CSR, PKCS#7 등 모든 DER 데이터에 쓸 수 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '해석', inLabel: 'PEM / DER', outLabel: 'ASN.1 트리', placeholder: '-----BEGIN … ----- 또는 Base64/16진수 DER' }],
    options: [fmtOption('inFmt', 'DER 입력 형식', 'base64', ['base64', 'hex'])],
    run: (s, o) => {
      const { label, der } = readDer(s, o.inFmt);
      return `${label} · ${der.length.toLocaleString()} B\n\n${asn1Tree(asn1Parse(der)).join('\n')}`;
    },
  });
})(globalThis.DecryptLab);
