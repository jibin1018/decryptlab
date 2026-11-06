/* 공개키 암호·전자서명·키 교환 (Web Crypto 기반) + 교과서 RSA */
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

  /* ---------- 교과서 RSA (BigInt) ---------- */
  const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  function modInv(a, m) {
    let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error('e와 φ(n)이 서로소가 아니라 d를 계산할 수 없습니다.');
    return ((s0 % m) + m) % m;
  }
  function iroot(n, k) {
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / Number(k)) + 1);
    for (;;) { const y = ((k - 1n) * x + n / x ** (k - 1n)) / k; if (y >= x) return x; x = y; }
  }
  const parseInt_ = (s, name) => {
    const t = String(s || '').trim().replace(/[\s_]/g, '');
    if (!t) return null;
    try { return BigInt(t); } catch { throw new Error(`${name} 값을 정수로 해석할 수 없습니다 (10진수 또는 0x16진수).`); }
  };
  function fermat(n, limit = 200000) {
    let a = iroot(n, 2n);
    if (a * a < n) a++;
    for (let i = 0; i < limit; i++, a++) {
      const b2 = a * a - n, b = iroot(b2, 2n);
      if (b * b === b2) return [a - b, a + b];
    }
    return null;
  }
  function trialDivide(n, limit = 100000) {
    if (n % 2n === 0n) return [2n, n / 2n];
    for (let p = 3n; p < BigInt(limit); p += 2n) if (n % p === 0n) return [p, n / p];
    return null;
  }
  const bigToText = (m) => {
    const b = bigToBytes(m);
    try { const t = DL.utf8Decode(b, true); if (DL.printableScore(t) > 0.9) return t; } catch { /* 바이너리 */ }
    return null;
  };
  function rsaSolve(cStr, o) {
    const c = parseInt_(cStr, '암호문 c');
    if (c === null) throw new Error('암호문 c를 입력하세요.');
    let n = parseInt_(o.n, 'n'), e = parseInt_(o.e, 'e') ?? 65537n, d = parseInt_(o.d, 'd');
    let p = parseInt_(o.p, 'p'), q = parseInt_(o.q, 'q');
    const log = [];
    if (p && q && !n) n = p * q;
    if (p && !q && n) q = n / p;
    if (!n) throw new Error('n(또는 p와 q)을 입력하세요.');
    if (!d && !(p && q)) {
      // 작은 e: m^e < n 이면 정수 e제곱근으로 바로 복원
      const m0 = iroot(c, e);
      if (m0 ** e === c) {
        log.push(`작은 지수 공격: m^${e} < n 이므로 c의 ${e}제곱근이 곧 평문입니다.`);
        return report(m0, log);
      }
      const f = trialDivide(n) || fermat(n);
      if (f) { [p, q] = f; log.push(`인수분해 성공 (${f[0] < 100000n ? '작은 소인수' : '페르마 — p와 q가 가까움'}): p = ${p}`); }
      else throw new Error('d나 p·q 없이 풀 수 없습니다. 작은 지수·작은 소인수·가까운 소수 공격이 모두 실패했습니다. (factordb.com 등에서 n의 인수분해를 확인해 보세요)');
    }
    if (!d) {
      const phi = (p - 1n) * (q - 1n);
      d = modInv(e, phi);
      log.push(`φ(n) = (p−1)(q−1), d = e⁻¹ mod φ(n) = ${d}`);
    }
    return report(modPow(c, d, n), log);
  }
  function report(m, log) {
    const text = bigToText(m);
    return [...log, '', `m (10진수)  ${m}`, `m (16진수)  0x${m.toString(16)}`, `m (텍스트)  ${text ?? '(읽을 수 있는 텍스트가 아님)'}`].join('\n');
  }

  Object.assign(DL.fn, { importKey, rawToDer, derToRaw, modPow, modInv, iroot, rsaSolve });

  /* ---------- 도구 정의 ---------- */
  const KEYGEN = { id: 'keygen', label: '키 생성', noInput: true, outLabel: '키 쌍 (PEM)' };
  const pemOpt = (id, label) => ({ id, label, type: 'textarea', default: '', wide: true, placeholder: '-----BEGIN … KEY----- 또는 JWK JSON' });

  const SIG_ALGS = {
    'ecdsa-p256': { gen: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' }, size: 32 },
    'ecdsa-p384': { gen: { name: 'ECDSA', namedCurve: 'P-384' }, sign: { name: 'ECDSA', hash: 'SHA-384' }, size: 48 },
    ed25519: { gen: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
    'rsa-pss': { gen: { name: 'RSA-PSS', hash: 'SHA-256', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, sign: { name: 'RSA-PSS', saltLength: 32 } },
    'rsa-pkcs1': { gen: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
  };
  const importAlg = (a) => { const g = { ...a.gen }; delete g.modulusLength; delete g.publicExponent; return g; };
  const isEcdsa = (o) => o.alg.startsWith('ecdsa');

  const KX = {
    'ecdh-p256': { gen: { name: 'ECDH', namedCurve: 'P-256' }, bits: 256 },
    'ecdh-p384': { gen: { name: 'ECDH', namedCurve: 'P-384' }, bits: 384 },
    x25519: { gen: { name: 'X25519' }, bits: 256 },
  };

  DL.addCategory({
    id: 'asymmetric',
    name: '공개키 암호·서명',
    desc: 'RSA-OAEP 암호화, ECDSA·Ed25519·RSA 전자서명, ECDH·X25519 키 교환, CTF용 교과서 RSA 풀이',
    color: 'indigo',
    tools: [
      {
        id: 'rsa', name: 'RSA-OAEP', short: '공개키 암호화 · 개인키 복호화',
        desc: '공개키로 암호화하고 개인키로 복호화합니다. OAEP는 현재 권장되는 RSA 패딩입니다. PEM(PKCS#8·PKCS#1·SPKI), 인증서, JWK를 모두 받습니다.',
        slow: true,
        modes: [
          { id: 'encrypt', label: '암호화', inLabel: '평문', outLabel: '암호문' },
          { id: 'decrypt', label: '복호화', inLabel: '암호문', outLabel: '평문' },
          KEYGEN,
        ],
        options: [
          { id: 'hash', label: 'OAEP 해시', type: 'select', default: 'SHA-256', choices: [['SHA-256', 'SHA-256'], ['SHA-1', 'SHA-1'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']] },
          { id: 'bits', label: '키 길이', type: 'select', default: '2048', mode: 'keygen', choices: [['2048', '2048비트'], ['3072', '3072비트'], ['4096', '4096비트']] },
          { ...pemOpt('pub', '공개키'), mode: 'encrypt' },
          { ...pemOpt('priv', '개인키'), mode: 'decrypt' },
          { ...fmtOption('ctFmt', '암호문 형식', 'base64', ['base64', 'hex']), mode: ['encrypt', 'decrypt'] },
        ],
        keygen: async (_, o) => {
          try {
            return await exportPair(await subtle().generateKey({ name: 'RSA-OAEP', modulusLength: Number(o.bits), publicExponent: Uint8Array.of(1, 0, 1), hash: o.hash }, true, ['encrypt', 'decrypt']));
          } catch (e) { throw webcryptoError(e); }
        },
        encrypt: async (s, o) => {
          const key = await importKey(o.pub, { name: 'RSA-OAEP', hash: o.hash }, ['encrypt'], 'public');
          try { return formatBytes(new Uint8Array(await subtle().encrypt({ name: 'RSA-OAEP' }, key, utf8(s))), o.ctFmt); }
          catch { throw new Error('암호화 실패 — 평문이 키 길이에 비해 너무 깁니다. (2048비트·SHA-256 기준 최대 190 B)'); }
        },
        decrypt: async (s, o) => {
          const key = await importKey(o.priv, { name: 'RSA-OAEP', hash: o.hash }, ['decrypt'], 'private');
          try { return formatBytes(new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, key, readBytes(s.trim(), o.ctFmt))), 'text'); }
          catch (e) { if (/UTF-8/.test(e.message)) throw e; throw new Error('복호화 실패 — 키가 맞지 않거나, OAEP 해시 설정이 다르거나, 암호문이 손상되었습니다.'); }
        },
      },
      {
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
      },
      {
        id: 'keyexchange', name: '키 교환', short: 'ECDH · X25519 공유 비밀',
        desc: '내 개인키와 상대방 공개키로 양쪽이 같은 공유 비밀을 계산합니다. 이 값은 보통 HKDF를 거쳐 대칭키로 쓰입니다. 입력 칸에 상대방 공개키를 넣으세요.',
        slow: true,
        modes: [
          { id: 'derive', label: '공유 비밀 계산', inLabel: '상대방 공개키', outLabel: '공유 비밀', placeholder: '-----BEGIN PUBLIC KEY----- …' },
          KEYGEN,
        ],
        options: [
          { id: 'alg', label: '알고리즘', type: 'select', default: 'x25519', choices: [['x25519', 'X25519'], ['ecdh-p256', 'ECDH P-256'], ['ecdh-p384', 'ECDH P-384']] },
          { ...pemOpt('priv', '내 개인키'), mode: 'derive' },
        ],
        keygen: async (_, o) => {
          try { return await exportPair(await subtle().generateKey(KX[o.alg].gen, true, ['deriveBits'])); } catch (e) { throw webcryptoError(e); }
        },
        derive: async (s, o) => {
          const a = KX[o.alg];
          const peer = await importKey(s, a.gen, [], 'public');
          const mine = await importKey(o.priv, a.gen, ['deriveBits'], 'private');
          try { return toHex(new Uint8Array(await subtle().deriveBits({ name: a.gen.name, public: peer }, mine, a.bits))); }
          catch (e) { throw webcryptoError(e); }
        },
      },
      {
        id: 'rsamath', name: '교과서 RSA (CTF)', short: 'n·e·c로 평문 복원 · 약점 공격',
        desc: '숫자로 주어진 RSA 문제를 풉니다. p·q나 d를 알면 바로 복호화하고, n과 e만 있으면 작은 지수(m^e < n), 작은 소인수, 가까운 소수(페르마) 공격을 차례로 시도합니다.',
        slow: true,
        modes: [
          { id: 'decrypt', label: '복호화', inLabel: '암호문 c', placeholder: '정수 (10진수 또는 0x16진수)' },
          { id: 'encrypt', label: '암호화', inLabel: '평문', outLabel: '암호문 c' },
        ],
        options: [
          { id: 'n', label: 'n', type: 'text', default: '', wide: true },
          { id: 'e', label: 'e', type: 'text', default: '65537' },
          { id: 'd', label: 'd (선택)', type: 'text', default: '', wide: true, mode: 'decrypt' },
          { id: 'p', label: 'p (선택)', type: 'text', default: '', mode: 'decrypt' },
          { id: 'q', label: 'q (선택)', type: 'text', default: '', mode: 'decrypt' },
        ],
        decrypt: (s, o) => rsaSolve(s, o),
        encrypt: (s, o) => {
          const n = parseInt_(o.n, 'n'), e = parseInt_(o.e, 'e') ?? 65537n;
          if (!n) throw new Error('n을 입력하세요.');
          const m = bigFromBytes(utf8(s));
          if (m >= n) throw new Error('평문이 n보다 큽니다. 더 짧은 평문이나 큰 n을 사용하세요.');
          const c = modPow(m, e, n);
          return `c (10진수)  ${c}\nc (16진수)  0x${c.toString(16)}`;
        },
      },
    ],
  });
})(globalThis.DecryptLab);
