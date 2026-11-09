/* 공개키 암호·서명 › 전자서명 */
(function (DL) {
  'use strict';
  const { utf8, readBytes, formatBytes, fmtOption, concat, subtle, der, asn1Parse, bigFromBytes, bigToBytes, importKey, exportPair, webcryptoError, KEYGEN, pemOpt } = DL.kits.asymmetric;

  /* ---------- ECDSA 서명 형식 변환 (raw r||s ↔ DER) ---------- */
  function rawToDer(raw) {
    const half = raw.length / 2;
    const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); return der(0x02, b[0] & 0x80 ? concat(Uint8Array.of(0), b) : b); };
    return der(0x30, int(raw.slice(0, half)), int(raw.slice(half)));
  }
  function derToRaw(sig, size) {
    const seq = asn1Parse(sig)[0];
    if (!seq || !seq.children || seq.children.length !== 2) throw new Error('DER 형식 ECDSA 서명이 아닙니다.');
    return concat(...seq.children.map((c) => bigToBytes(bigFromBytes(c.value), size)));
  }
  Object.assign(DL.fn, { rawToDer, derToRaw });

  const SIG_ALGS = {
    'ecdsa-p256': { gen: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' }, size: 32 },
    'ecdsa-p384': { gen: { name: 'ECDSA', namedCurve: 'P-384' }, sign: { name: 'ECDSA', hash: 'SHA-384' }, size: 48 },
    ed25519: { gen: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
    'rsa-pss': { gen: { name: 'RSA-PSS', hash: 'SHA-256', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, sign: { name: 'RSA-PSS', saltLength: 32 } },
    'rsa-pkcs1': { gen: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
  };
  const importAlg = (a) => { const g = { ...a.gen }; delete g.modulusLength; delete g.publicExponent; return g; };
  const isEcdsa = (o) => o.alg.startsWith('ecdsa');

  DL.addTool('asymmetric', {
    id: 'signature', name: '전자서명', short: 'ECDSA · Ed25519 · RSA-PSS',
    desc: '개인키로 메시지에 서명하고 공개키로 검증합니다. 전자서명은 암호화가 아니라 "누가 보냈고 변조되지 않았는지"를 증명합니다. ECDSA 서명은 JWT에서 쓰는 raw(r‖s)와 OpenSSL의 DER 형식을 모두 지원합니다.',
    slow: true,
    modes: [
      { id: 'sign', label: '서명', inLabel: '메시지', outLabel: '서명값' },
      { id: 'verify', label: '검증', inLabel: '메시지', outLabel: '검증 결과' },
      KEYGEN,
    ],
    options: [
      { id: 'alg', label: '알고리즘', type: 'select', default: 'ecdsa-p256', choices: [['ecdsa-p256', 'ECDSA P-256 / SHA-256'], ['ecdsa-p384', 'ECDSA P-384 / SHA-384'], ['ed25519', 'Ed25519'], ['rsa-pss', 'RSA-PSS / SHA-256'], ['rsa-pkcs1', 'RSASSA-PKCS1-v1_5 / SHA-256']] },
      { ...pemOpt('priv', '개인키'), mode: 'sign' },
      { ...pemOpt('pub', '공개키'), mode: 'verify' },
      { id: 'sig', label: '서명값', type: 'text', default: '', mode: 'verify', wide: true },
      { ...fmtOption('sigFmt', '서명 형식', 'base64', ['base64', 'hex']), mode: ['sign', 'verify'] },
      { id: 'sigEnc', label: 'ECDSA 인코딩', type: 'select', default: 'raw', mode: ['sign', 'verify'], when: isEcdsa, choices: [['raw', 'raw r‖s (JWT·WebCrypto)'], ['der', 'DER (OpenSSL)']] },
    ],
    keygen: async (_, o) => {
      const a = SIG_ALGS[o.alg];
      try { return await exportPair(await subtle().generateKey(a.gen, true, ['sign', 'verify'])); } catch (e) { throw webcryptoError(e); }
    },
    sign: async (s, o) => {
      const a = SIG_ALGS[o.alg];
      const key = await importKey(o.priv, importAlg(a), ['sign'], 'private');
      let sig;
      try { sig = new Uint8Array(await subtle().sign(a.sign, key, utf8(s))); } catch (e) { throw webcryptoError(e); }
      if (isEcdsa(o) && o.sigEnc === 'der') sig = rawToDer(sig);
      return formatBytes(sig, o.sigFmt);
    },
    verify: async (s, o) => {
      const a = SIG_ALGS[o.alg];
      const key = await importKey(o.pub, importAlg(a), ['verify'], 'public');
      if (!o.sig.trim()) throw new Error('"서명값" 칸에 검증할 서명을 넣으세요.');
      let sig = readBytes(o.sig.trim(), o.sigFmt);
      if (isEcdsa(o) && o.sigEnc === 'der') sig = derToRaw(sig, a.size);
      let ok;
      try { ok = await subtle().verify(a.sign, key, sig, utf8(s)); } catch (e) { throw webcryptoError(e); }
      return ok ? '✓ 유효한 서명입니다 — 이 메시지는 해당 개인키로 서명되었고 변조되지 않았습니다.' : '✗ 서명이 유효하지 않습니다 — 메시지·서명·공개키 중 하나가 다르거나 변조되었습니다.';
    },
  });
})(globalThis.DecryptLab);
