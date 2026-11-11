/* 공개키 암호·전자서명·키 교환 — 카테고리 셸 + 공유 헬퍼 (DL.kits.asymmetric) */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex, readBytes, formatBytes, fmtOption, concat, subtle, toPem, fromPem, asn1Parse, der, derOid, bigFromBytes, bigToBytes, b64decode } = DL;

  /* ---------- 키 가져오기 (PEM · PKCS#1 · SEC1 · 인증서 · JWK) ---------- */
  const OID_RSA = '1.2.840.113549.1.1.1', OID_EC = '1.2.840.10045.2.1';
  const NULL = Uint8Array.of(5, 0);
  const wrapRsaSpki = (pkcs1) => der(0x30, der(0x30, derOid(OID_RSA), NULL), der(0x03, Uint8Array.of(0), pkcs1));
  const wrapRsaPkcs8 = (pkcs1) => der(0x30, der(0x02, Uint8Array.of(0)), der(0x30, derOid(OID_RSA), NULL), der(0x04, pkcs1));
  function wrapSec1(sec1) {
    const seq = asn1Parse(sec1)[0];
    const params = seq.children.find((c) => c.cls === 2 && c.tag === 0);
    if (!params) throw new Error('EC 개인키에 곡선 정보가 없습니다.');
    const curve = params.children[0];
    const curveDer = sec1.subarray(curve.offset, curve.offset + curve.hdrLen + curve.len);
    return der(0x30, der(0x02, Uint8Array.of(0)), der(0x30, derOid(OID_EC), curveDer), der(0x04, sec1));
  }
  function spkiFromCert(cert) {
    const tbs = asn1Parse(cert)[0].children[0];
    const ch = tbs.children;
    const off = ch[0].cls === 2 ? 1 : 0;
    const spki = ch[off + 5];
    return cert.subarray(spki.offset, spki.offset + spki.hdrLen + spki.len);
  }
  async function importKey(text, alg, usages, kind) {
    const t = (text || '').trim();
    const what = kind === 'public' ? '공개키' : '개인키';
    if (!t) throw new Error(`${what}를 "${what}" 칸에 붙여 넣으세요 (PEM 또는 JWK).`);
    let format, data;
    if (t.startsWith('{')) {
      format = 'jwk';
      try { data = JSON.parse(t); } catch { throw new Error('JWK JSON을 해석할 수 없습니다.'); }
      if (kind === 'private' && !data.d) throw new Error('이 JWK에는 개인키(d)가 없습니다.');
    } else {
      const { label, der: d } = fromPem(t);
      const map = {
        'PUBLIC KEY': ['spki', d, 'public'], 'PRIVATE KEY': ['pkcs8', d, 'private'],
        'RSA PUBLIC KEY': ['spki', () => wrapRsaSpki(d), 'public'], 'RSA PRIVATE KEY': ['pkcs8', () => wrapRsaPkcs8(d), 'private'],
        'EC PRIVATE KEY': ['pkcs8', () => wrapSec1(d), 'private'], CERTIFICATE: ['spki', () => spkiFromCert(d), 'public'],
      };
      if (!map[label]) throw new Error(`지원하지 않는 PEM 종류입니다: ${label}`);
      const [f, dd, k] = map[label];
      if (k !== kind) throw new Error(`${what}가 필요한데 ${k === 'public' ? '공개키' : '개인키'}(${label})가 입력되었습니다.`);
      format = f; data = typeof dd === 'function' ? dd() : dd;
    }
    try { return await subtle().importKey(format, data, alg, true, usages); }
    catch (e) { throw new Error(`키를 가져올 수 없습니다 — 알고리즘이나 곡선이 키와 맞는지 확인하세요. (${e.message || e.name})`); }
  }
  async function exportPair(pair) {
    const pub = new Uint8Array(await subtle().exportKey('spki', pair.publicKey));
    const priv = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
    return `${toPem(priv, 'PRIVATE KEY')}\n\n${toPem(pub, 'PUBLIC KEY')}`;
  }
  const webcryptoError = (e) => {
    if (e && /not supported|NotSupported|Unrecognized/i.test(`${e.name} ${e.message}`)) return new Error('이 브라우저는 해당 알고리즘을 지원하지 않습니다. 최신 Chrome/Firefox/Safari를 사용하세요.');
    return e;
  };
  DL.fn.importKey = importKey;

  const KEYGEN = { id: 'keygen', label: '키 생성', noInput: true, outLabel: '키 쌍 (PEM)' };
  const pemOpt = (id, label) => ({ id, label, type: 'textarea', default: '', wide: true, placeholder: '-----BEGIN … KEY----- 또는 JWK JSON' });

  DL.kits.asymmetric = {
    utf8, toHex, fromHex, readBytes, formatBytes, fmtOption, concat, subtle, der, asn1Parse, bigFromBytes, bigToBytes, b64decode,
    importKey, exportPair, webcryptoError, KEYGEN, pemOpt,
  };

  DL.addCategory({
    id: 'asymmetric',
    name: '공개키 암호·서명',
    desc: 'RSA·ECDSA·키 교환·전자서명',
    color: 'indigo',
    tools: [],
  });
})(globalThis.DecryptLab);
