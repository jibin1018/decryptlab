/* 웹 토큰·인증서 */
(function (DL) {
  'use strict';
  const { utf8, utf8Decode, b64decode, b64encode, toHex, fromPem, toPem, asn1Parse, oidToString, bigFromBytes, subtle, readBytes, fmtOption, latin1, concat } = DL;
  const b64url = (b) => b64encode(b, { urlsafe: true, nopad: true });

  /* ---------- OID 이름 ---------- */
  const OIDS = {
    '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.7': 'RSAES-OAEP', '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.10045.2.1': 'ecPublicKey', '1.2.840.10045.3.1.7': 'P-256 (prime256v1)', '1.3.132.0.34': 'P-384 (secp384r1)', '1.3.132.0.35': 'P-521 (secp521r1)', '1.3.132.0.10': 'secp256k1',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448', '1.3.101.110': 'X25519', '1.3.101.111': 'X448',
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'street', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
    '2.5.4.4': 'SN', '2.5.4.42': 'GN', '2.5.4.12': 'title', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
    '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage', '2.5.29.17': 'subjectAltName', '2.5.29.18': 'issuerAltName', '2.5.29.19': 'basicConstraints',
    '2.5.29.31': 'cRLDistributionPoints', '2.5.29.32': 'certificatePolicies', '2.5.29.35': 'authorityKeyIdentifier', '2.5.29.37': 'extKeyUsage',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'caIssuers',
    '1.3.6.1.5.5.7.3.1': 'serverAuth (TLS 서버)', '1.3.6.1.5.5.7.3.2': 'clientAuth (TLS 클라이언트)', '1.3.6.1.5.5.7.3.3': 'codeSigning (코드 서명)',
    '1.3.6.1.5.5.7.3.4': 'emailProtection (S/MIME)', '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
    '1.3.6.1.4.1.11129.2.4.2': 'CT 서명 인증서 타임스탬프', '2.23.140.1.2.1': 'DV 인증서 정책', '2.23.140.1.2.2': 'OV 인증서 정책', '2.23.140.1.1': 'EV 인증서 정책',
    '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512', '1.3.14.3.2.26': 'sha1', '1.2.840.113549.2.5': 'md5',
    '1.2.840.113549.1.7.1': 'data', '1.2.840.113549.1.7.2': 'signedData', '1.2.840.113549.1.7.3': 'envelopedData',
    '1.2.840.113549.1.9.3': 'contentType', '1.2.840.113549.1.9.4': 'messageDigest', '1.2.840.113549.1.9.5': 'signingTime',
    '1.2.840.113549.1.5.13': 'PBES2', '1.2.840.113549.1.5.12': 'PBKDF2', '2.16.840.1.101.3.4.1.2': 'aes128-CBC', '2.16.840.1.101.3.4.1.42': 'aes256-CBC',
    '1.2.840.113549.2.9': 'hmacWithSHA256', '1.2.410.200004.1.4': 'SEED-CBC',
  };
  const oidName = (oid) => (OIDS[oid] ? `${OIDS[oid]} (${oid})` : oid);

  /* ---------- ASN.1 트리 ---------- */
  const UNIVERSAL = { 1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL', 6: 'OBJECT IDENTIFIER', 10: 'ENUMERATED', 12: 'UTF8String', 16: 'SEQUENCE', 17: 'SET', 19: 'PrintableString', 20: 'T61String', 22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime', 30: 'BMPString' };
  function parseTime(node) {
    const s = latin1(node.value);
    const m = node.tag === 23 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/.exec(s);
    if (!m) return null;
    let y = Number(m[1]);
    if (node.tag === 23) y += y < 50 ? 2000 : 1900;
    return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6] || 0));
  }
  function nodeValue(n) {
    if (n.cls !== 0) return n.constructed ? '' : `${toHex(n.value.subarray(0, 32))}${n.len > 32 ? '…' : ''}${/^[\x20-\x7e]+$/.test(latin1(n.value)) ? `  "${latin1(n.value)}"` : ''}`;
    switch (n.tag) {
      case 1: return n.value[0] ? 'TRUE' : 'FALSE';
      case 2: case 10: return n.len <= 8 ? String(bigFromBytes(n.value) - (n.value[0] & 0x80 ? 1n << BigInt(n.len * 8) : 0n)) : `${toHex(n.value.subarray(0, 24))}… (${(n.len - (n.value[0] === 0 ? 1 : 0)) * 8}비트)`;
      case 3: return n.children ? '(내부에 DER 포함)' : `미사용 비트 ${n.value[0]} · ${toHex(n.value.subarray(1, 33))}${n.len > 33 ? '…' : ''}`;
      case 4: if (n.children) return '(내부에 DER 포함)'; return `${toHex(n.value.subarray(0, 32))}${n.len > 32 ? '…' : ''}`;
      case 5: return '';
      case 6: return oidName(oidToString(n.value));
      case 12: return utf8Decode(n.value);
      case 30: { let s = ''; for (let i = 0; i + 1 < n.value.length; i += 2) s += String.fromCharCode((n.value[i] << 8) | n.value[i + 1]); return s; }
      case 19: case 20: case 22: return latin1(n.value);
      case 23: case 24: { const d = parseTime(n); return d ? d.toISOString() : latin1(n.value); }
      default: return n.constructed ? '' : toHex(n.value.subarray(0, 32));
    }
  }
  function asn1Tree(nodes, depth = 0, out = []) {
    for (const n of nodes) {
      const name = n.cls === 0 ? (UNIVERSAL[n.tag] || `UNIVERSAL ${n.tag}`) : n.cls === 2 ? `[${n.tag}]` : `${['', 'APPLICATION', '', 'PRIVATE'][n.cls]} ${n.tag}`;
      const v = nodeValue(n);
      out.push(`${String(n.offset).padStart(5)} ${'  '.repeat(depth)}${name} (${n.len})${v ? '  ' + v : ''}`);
      if (n.children) asn1Tree(n.children, depth + 1, out);
      if (out.length > 3000) { out.push('… (너무 길어 생략)'); break; }
    }
    return out;
  }
  function readDer(s, fmt) {
    if (s instanceof Uint8Array) {
      const t = latin1(s.subarray(0, 64));
      return t.includes('-----BEGIN') ? fromPem(utf8Decode(s)) : { label: '(DER 파일)', der: s };
    }
    if (/-----BEGIN/.test(s)) return fromPem(s);
    return { label: '(입력)', der: readBytes(s.trim(), fmt) };
  }

  /* ---------- X.509 ---------- */
  const nameStr = (seq) => (seq.children || []).map((set) => set.children.map((atv) => {
    const [oid, val] = atv.children;
    const key = OIDS[oidToString(oid.value)] || oidToString(oid.value);
    return `${key}=${nodeValue(val)}`;
  }).join('+')).join(', ');
  const KU = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
  function extDetail(oid, der) {
    const n = asn1Parse(der)[0];
    switch (oid) {
      case '2.5.29.17': case '2.5.29.18':
        return n.children.map((g) => {
          const v = g.value;
          if (g.tag === 2) return `DNS:${latin1(v)}`;
          if (g.tag === 1) return `email:${latin1(v)}`;
          if (g.tag === 6) return `URI:${latin1(v)}`;
          if (g.tag === 7) return `IP:${v.length === 4 ? Array.from(v).join('.') : toHex(v, false, ':')}`;
          return `[${g.tag}]`;
        }).join(', ');
      case '2.5.29.19': {
        const ca = n.children && n.children[0] && n.children[0].tag === 1 && n.children[0].value[0];
        const pl = n.children && n.children.find((c) => c.tag === 2);
        return `CA: ${ca ? '예 (인증 기관)' : '아니오 (최종 인증서)'}${pl ? `, pathLen ${bigFromBytes(pl.value)}` : ''}`;
      }
      case '2.5.29.15': {
        const unused = n.value[0], bits = [];
        for (let i = 0; i < (n.value.length - 1) * 8 - unused; i++) if (n.value[1 + (i >> 3)] & (0x80 >> (i & 7))) bits.push(KU[i]);
        return bits.join(', ');
      }
      case '2.5.29.37': return n.children.map((c) => OIDS[oidToString(c.value)] || oidToString(c.value)).join(', ');
      case '2.5.29.14': return toHex(n.value, true, ':');
      case '2.5.29.35': { const k = n.children.find((c) => c.cls === 2 && c.tag === 0); return k ? toHex(k.value, true, ':') : ''; }
      case '1.3.6.1.5.5.7.1.1': return n.children.map((ad) => `${OIDS[oidToString(ad.children[0].value)] || ''} ${latin1(ad.children[1].value)}`).join(', ');
      case '2.5.29.31': {
        const uris = [];
        const walk = (x) => { if (x.cls === 2 && x.tag === 6 && !x.constructed) uris.push(latin1(x.value)); (x.children || []).forEach(walk); };
        walk(n);
        return uris.join(', ');
      }
      case '2.5.29.32': return n.children.map((p) => OIDS[oidToString(p.children[0].value)] || oidToString(p.children[0].value)).join(', ');
      default: return `${der.length} B`;
    }
  }
  async function x509Report(der) {
    const cert = asn1Parse(der)[0];
    if (!cert || !cert.children || cert.children.length !== 3) throw new Error('X.509 인증서 구조가 아닙니다 (SEQUENCE { tbsCertificate, 서명 알고리즘, 서명 }).');
    const tbs = cert.children[0].children;
    const off = tbs[0].cls === 2 ? 1 : 0;
    const version = off ? Number(bigFromBytes(tbs[0].children[0].value)) + 1 : 1;
    const serial = toHex(tbs[off].value, true, ':');
    const sigAlg = oidToString(tbs[off + 1].children[0].value);
    const [nb, na] = tbs[off + 3].children.map(parseTime);
    const spki = tbs[off + 5];
    const keyOid = oidToString(spki.children[0].children[0].value);
    let keyDesc = OIDS[keyOid] || keyOid;
    if (keyOid === '1.2.840.113549.1.1.1') {
      const rsa = spki.children[1].children[0].children;
      const n = rsa[0].value;
      keyDesc = `RSA ${(n.length - (n[0] === 0 ? 1 : 0)) * 8}비트, e=${bigFromBytes(rsa[1].value)}`;
    } else if (keyOid === '1.2.840.10045.2.1') keyDesc = `EC ${OIDS[oidToString(spki.children[0].children[1].value)] || ''}`;
    const now = new Date();
    const status = now < nb ? '⚠ 아직 유효 기간 전' : now > na ? '✗ 만료됨' : `✓ 유효 (${Math.ceil((na - now) / 86400000)}일 남음)`;
    const issuer = nameStr(tbs[off + 2]), subject = nameStr(tbs[off + 4]);
    const lines = [
      `주체 (Subject)     ${subject}`, `발급자 (Issuer)    ${issuer}${issuer === subject ? '  ← 자체 서명 인증서' : ''}`,
      `유효 기간          ${nb.toISOString()} ~ ${na.toISOString()}`, `상태               ${status}`,
      `공개키             ${keyDesc}`, `서명 알고리즘      ${OIDS[sigAlg] || sigAlg}`, `일련번호           ${serial}`, `버전               v${version}`,
    ];
    const extWrap = tbs.find((c) => c.cls === 2 && c.tag === 3);
    if (extWrap) {
      lines.push('', '■ 확장 필드');
      for (const ext of extWrap.children[0].children) {
        const oid = oidToString(ext.children[0].value);
        const critical = ext.children.length === 3 && ext.children[1].value[0];
        const oct = ext.children[ext.children.length - 1];
        let detail;
        try { detail = extDetail(oid, oct.value); } catch { detail = '(해석 불가)'; }
        lines.push(`  ${(OIDS[oid] || oid).padEnd(24)}${critical ? ' [중요]' : ''}  ${detail}`);
      }
    }
    if (subject.includes('CN=') && !lines.some((l) => l.includes('subjectAltName'))) lines.push('', '⚠ SAN이 없습니다 — 최신 브라우저는 CN만 있는 서버 인증서를 신뢰하지 않습니다.');
    const fp = async (a) => toHex(new Uint8Array(await subtle().digest(a, der)), true, ':');
    lines.push('', '■ 지문', `  SHA-256  ${await fp('SHA-256')}`, `  SHA-1    ${await fp('SHA-1')}`);
    return lines.join('\n');
  }

  /* ---------- JWT ---------- */
  function jwtParts(token) {
    const parts = token.trim().split('.');
    if (parts.length === 5) throw new Error('점이 4개인 토큰은 JWE(암호화된 JWT)입니다. 페이로드를 보려면 복호화 키가 필요합니다.');
    if (parts.length !== 3) throw new Error('JWT는 점(.)으로 구분된 header.payload.signature 형식이어야 합니다.');
    const parse = (p, name) => { try { return JSON.parse(utf8Decode(b64decode(p), true)); } catch { throw new Error(`${name}를 해석할 수 없습니다.`); } };
    return { parts, header: parse(parts[0], 'Header'), payload: parse(parts[1], 'Payload') };
  }
  function jwtDecode(token) {
    const { parts, header, payload } = jwtParts(token.trim().split('.').length === 2 ? token.trim() + '.' : token);
    let out = `// Header\n${JSON.stringify(header, null, 2)}\n\n// Payload\n${JSON.stringify(payload, null, 2)}\n`;
    const times = ['iat', 'nbf', 'exp'].filter((k) => typeof payload[k] === 'number');
    if (times.length) {
      out += '\n// 시간 클레임\n';
      const now = Date.now() / 1000;
      for (const k of times) {
        let note = '';
        if (k === 'exp') note = payload[k] < now ? '  ← 만료됨' : '  ← 유효';
        if (k === 'nbf' && payload[k] > now) note = '  ← 아직 사용 불가';
        out += `${k}: ${new Date(payload[k] * 1000).toISOString()}${note}\n`;
      }
    }
    out += `\n// Signature (${header.alg || '알 수 없음'})\n${parts[2] || '(없음)'}\n`;
    if (String(header.alg).toLowerCase() === 'none') out += '\n⚠ alg가 none입니다 — 서명 검증이 비활성화된 토큰입니다.\n';
    return out;
  }
  const JWT_ALGS = {
    HS256: { kind: 'hmac', hash: 'SHA-256' }, HS384: { kind: 'hmac', hash: 'SHA-384' }, HS512: { kind: 'hmac', hash: 'SHA-512' },
    RS256: { imp: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
    RS384: { imp: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
    RS512: { imp: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
    PS256: { imp: { name: 'RSA-PSS', hash: 'SHA-256' }, sign: { name: 'RSA-PSS', saltLength: 32 } },
    PS384: { imp: { name: 'RSA-PSS', hash: 'SHA-384' }, sign: { name: 'RSA-PSS', saltLength: 48 } },
    PS512: { imp: { name: 'RSA-PSS', hash: 'SHA-512' }, sign: { name: 'RSA-PSS', saltLength: 64 } },
    ES256: { imp: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' } },
    ES384: { imp: { name: 'ECDSA', namedCurve: 'P-384' }, sign: { name: 'ECDSA', hash: 'SHA-384' } },
    ES512: { imp: { name: 'ECDSA', namedCurve: 'P-521' }, sign: { name: 'ECDSA', hash: 'SHA-512' } },
    EdDSA: { imp: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
  };
  const secretBytes = (o) => (o.secretFmt === 'base64' ? b64decode(o.key.trim()) : utf8(o.key));
  async function jwtVerify(token, o) {
    const { parts, header } = jwtParts(token);
    const alg = header.alg;
    if (!alg || String(alg).toLowerCase() === 'none') return '✗ alg가 none입니다 — 서명이 없는 토큰이므로 절대 신뢰하면 안 됩니다.';
    const a = JWT_ALGS[alg];
    if (!a) throw new Error(`지원하지 않는 알고리즘입니다: ${alg}`);
    if (!o.key.trim()) throw new Error(a.kind === 'hmac' ? '"키" 칸에 HMAC 비밀키를 넣으세요.' : '"키" 칸에 공개키(PEM 또는 JWK)를 넣으세요.');
    const data = utf8(`${parts[0]}.${parts[1]}`);
    const sig = b64decode(parts[2]);
    let ok;
    if (a.kind === 'hmac') {
      const expected = await DL.fn.hmac(a.hash, secretBytes(o), data);
      ok = expected.length === sig.length && expected.every((v, i) => v === sig[i]);
    } else {
      const key = await DL.fn.importKey(o.key, a.imp, ['verify'], 'public');
      ok = await subtle().verify(a.sign, key, sig, data);
    }
    return `${ok ? '✓ 서명이 유효합니다.' : '✗ 서명이 유효하지 않습니다 — 키가 다르거나 토큰이 변조되었습니다.'}  (alg: ${alg})\n\n${jwtDecode(token)}`;
  }
  async function jwtSign(payloadText, o) {
    let payload;
    try { payload = JSON.parse(payloadText); } catch { throw new Error('페이로드는 JSON이어야 합니다. 예: {"sub":"1234","name":"홍길동"}'); }
    const a = JWT_ALGS[o.alg];
    if (!o.key.trim()) throw new Error(a.kind === 'hmac' ? '"키" 칸에 HMAC 비밀키를 넣으세요.' : '"키" 칸에 개인키(PEM 또는 JWK)를 넣으세요.');
    const input = `${b64url(utf8(JSON.stringify({ alg: o.alg, typ: 'JWT' })))}.${b64url(utf8(JSON.stringify(payload)))}`;
    let sig;
    if (a.kind === 'hmac') sig = await DL.fn.hmac(a.hash, secretBytes(o), utf8(input));
    else sig = new Uint8Array(await subtle().sign(a.sign, await DL.fn.importKey(o.key, a.imp, ['sign'], 'private'), utf8(input)));
    return `${input}.${b64url(sig)}`;
  }

  /* ---------- JWK ---------- */
  function jwkAlg(jwk) {
    if (jwk.kty === 'RSA') return { name: 'RSA-PSS', hash: 'SHA-256' };
    if (jwk.kty === 'EC') return { name: 'ECDSA', namedCurve: jwk.crv };
    if (jwk.kty === 'OKP') return { name: jwk.crv };
    throw new Error(`지원하지 않는 kty입니다: ${jwk.kty} (oct 대칭키는 PEM으로 바꿀 수 없습니다)`);
  }
  async function thumbprint(jwk) {
    const req = { RSA: ['e', 'kty', 'n'], EC: ['crv', 'kty', 'x', 'y'], OKP: ['crv', 'kty', 'x'] }[jwk.kty];
    const json = `{${req.map((k) => `"${k}":"${jwk[k]}"`).join(',')}}`;
    return b64url(new Uint8Array(await subtle().digest('SHA-256', utf8(json))));
  }
  async function jwkToPem(text) {
    let j;
    try { j = JSON.parse(text); } catch { throw new Error('JWK JSON을 해석할 수 없습니다.'); }
    const keys = Array.isArray(j.keys) ? j.keys : [j];
    const out = [];
    for (const k of keys) {
      const alg = jwkAlg(k);
      const pub = { ...k }; delete pub.d; delete pub.p; delete pub.q; delete pub.dp; delete pub.dq; delete pub.qi; delete pub.key_ops; delete pub.alg; delete pub.use;
      const head = `# ${k.kid ? `kid=${k.kid} · ` : ''}${k.kty}${k.crv ? ' ' + k.crv : ''}${k.alg ? ' · ' + k.alg : ''} · thumbprint ${await thumbprint(k)}`;
      const blocks = [head];
      if (k.d) {
        const priv = { ...k }; delete priv.key_ops; delete priv.alg; delete priv.use;
        const key = await subtle().importKey('jwk', priv, alg, true, alg.name === 'X25519' ? ['deriveBits'] : ['sign']);
        blocks.push(toPem(new Uint8Array(await subtle().exportKey('pkcs8', key)), 'PRIVATE KEY'));
      }
      const pk = await subtle().importKey('jwk', pub, alg, true, alg.name === 'X25519' ? [] : ['verify']);
      blocks.push(toPem(new Uint8Array(await subtle().exportKey('spki', pk)), 'PUBLIC KEY'));
      out.push(blocks.join('\n'));
    }
    return out.join('\n\n');
  }
  async function pemToJwk(text) {
    const { label, der } = fromPem(text);
    const kind = /PRIVATE/.test(label) ? 'private' : 'public';
    // 알고리즘 OID로 가져오기 방식을 정한다
    const flat = [];
    const walk = (ns) => ns.forEach((n) => { if (n.tag === 6 && n.cls === 0) flat.push(oidToString(n.value)); if (n.children) walk(n.children); });
    walk(asn1Parse(label === 'CERTIFICATE' ? der : der));
    let alg;
    if (/^RSA /.test(label) || flat.includes('1.2.840.113549.1.1.1')) alg = { name: 'RSA-PSS', hash: 'SHA-256' };
    else if (flat.includes('1.2.840.10045.2.1') || label === 'EC PRIVATE KEY') {
      const crv = flat.includes('1.3.132.0.34') ? 'P-384' : flat.includes('1.3.132.0.35') ? 'P-521' : 'P-256';
      alg = { name: 'ECDSA', namedCurve: crv };
    } else if (flat.includes('1.3.101.112')) alg = { name: 'Ed25519' };
    else if (flat.includes('1.3.101.110')) alg = { name: 'X25519' };
    else throw new Error('키 알고리즘을 알 수 없습니다.');
    const usages = kind === 'private' ? (alg.name === 'X25519' ? ['deriveBits'] : ['sign']) : (alg.name === 'X25519' ? [] : ['verify']);
    const key = await DL.fn.importKey(text, alg, usages, kind);
    const jwk = await subtle().exportKey('jwk', key);
    delete jwk.key_ops; delete jwk.ext; delete jwk.alg;
    jwk.kid = await thumbprint(jwk);
    return JSON.stringify(jwk, null, 2);
  }

  /* ---------- SAML ---------- */
  function prettyXml(xml) {
    let depth = 0;
    return xml.replace(/>\s*</g, '>\n<').split('\n').map((line) => {
      if (/^<\//.test(line)) depth = Math.max(0, depth - 1);
      const out = '  '.repeat(depth) + line;
      if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line)) depth++;
      return out;
    }).join('\n');
  }
  async function samlDecode(s) {
    let t = s.trim();
    const m = /(?:SAMLRequest|SAMLResponse)=([^&\s]+)/.exec(t);
    if (m) t = m[1];
    if (/%[0-9a-f]{2}/i.test(t)) t = decodeURIComponent(t.replace(/\+/g, ' '));
    const bytes = b64decode(t);
    let xml;
    let how = 'Base64 (HTTP-POST 바인딩)';
    try { xml = utf8Decode(bytes, true); if (!xml.trim().startsWith('<')) throw new Error(); }
    catch {
      xml = utf8Decode((await DL.fn.decompress(bytes, 'raw')).out);
      how = 'Base64 + Raw DEFLATE (HTTP-Redirect 바인딩)';
    }
    const notes = [`// 인코딩: ${how}`];
    if (/<(\w+:)?Signature[\s>]/.test(xml)) notes.push('// 서명 포함 (검증은 하지 않음)');
    if (/<(\w+:)?EncryptedAssertion/.test(xml)) notes.push('// 암호화된 Assertion 포함 — 내용 확인에는 SP 개인키가 필요합니다');
    return `${notes.join('\n')}\n\n${prettyXml(xml)}`;
  }

  /* ---------- JWE (RFC 7516) ---------- */
  const JWE_ENC = {
    A128GCM: { gcm: true, len: 16 }, A192GCM: { gcm: true, len: 24 }, A256GCM: { gcm: true, len: 32 },
    'A128CBC-HS256': { len: 32, hash: 'SHA-256', tag: 16 }, 'A192CBC-HS384': { len: 48, hash: 'SHA-384', tag: 24 }, 'A256CBC-HS512': { len: 64, hash: 'SHA-512', tag: 32 },
  };
  function symKey(o) {
    const t = o.key.trim();
    if (t.startsWith('{')) {
      let j; try { j = JSON.parse(t); } catch { throw new Error('JWK JSON을 해석할 수 없습니다.'); }
      if (!j.k) throw new Error('대칭키 JWK(kty: "oct")에는 k 값이 있어야 합니다.');
      return b64decode(j.k);
    }
    return o.keyFmt === 'hex' ? DL.fromHex(t) : o.keyFmt === 'text' ? utf8(t) : b64decode(t);
  }
  async function jweDecrypt(token, o) {
    const parts = token.trim().split('.');
    if (parts.length !== 5) throw new Error('JWE Compact 형식은 점(.)으로 구분된 5개 부분(header.key.iv.ciphertext.tag)이어야 합니다.');
    const [h64, ek64, iv64, ct64, tag64] = parts;
    let header;
    try { header = JSON.parse(utf8Decode(b64decode(h64), true)); } catch { throw new Error('JWE 헤더를 해석할 수 없습니다.'); }
    const { alg, enc } = header;
    const head = `// Header\n${JSON.stringify(header, null, 2)}\n`;
    const e = JWE_ENC[enc];
    if (!e) return `${head}\n✗ 지원하지 않는 콘텐츠 암호화 방식입니다: ${enc}`;
    if (!o.key.trim()) return `${head}\n키를 입력하면 복호화합니다. (alg ${alg}: ${alg === 'dir' ? '콘텐츠 암호화 키(CEK) 자체' : /^RSA/.test(alg) ? 'RSA 개인키 PEM/JWK' : /KW$/.test(alg) ? '키 래핑용 AES 키' : '지원하지 않음'})`;
    let cek;
    if (alg === 'dir') cek = symKey(o);
    else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
      const key = await DL.fn.importKey(o.key, { name: 'RSA-OAEP', hash: alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256' }, ['decrypt'], 'private');
      try { cek = new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, key, b64decode(ek64))); }
      catch { throw new Error('암호화된 키(CEK)를 풀 수 없습니다 — 다른 RSA 키로 암호화된 토큰입니다.'); }
    } else if (/^A(128|192|256)KW$/.test(alg)) {
      const kek = symKey(o);
      if (kek.length * 8 !== Number(alg.slice(1, 4))) throw new Error(`${alg}에는 ${alg.slice(1, 4)}비트(${Number(alg.slice(1, 4)) / 8} B) 키가 필요합니다. (현재 ${kek.length} B)`);
      const wrapped = b64decode(ek64);
      try {
        const k = await subtle().importKey('raw', kek, 'AES-KW', false, ['unwrapKey']);
        const raw = await subtle().unwrapKey('raw', wrapped, k, 'AES-KW', { name: 'HMAC', hash: 'SHA-256', length: (wrapped.length - 8) * 8 }, true, ['sign']);
        cek = new Uint8Array(await subtle().exportKey('raw', raw));
      } catch { throw new Error('키 래핑을 풀 수 없습니다 — AES 키가 맞지 않습니다.'); }
    } else return `${head}\n✗ 지원하지 않는 키 관리 방식입니다: ${alg} (지원: dir, RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, A256KW)`;
    if (cek.length !== e.len) throw new Error(`${enc}에는 ${e.len} B 콘텐츠 키가 필요한데 ${cek.length} B입니다.`);
    const aad = utf8(h64), iv = b64decode(iv64), ct = b64decode(ct64), tag = b64decode(tag64);
    let pt;
    if (e.gcm) {
      try { pt = DL.fn.blockCrypt(DL.fn.AES, cek, iv, concat(ct, tag), { mode: 'gcm', aad: h64 }, true); }
      catch { throw new Error('복호화 실패 — 인증 태그가 맞지 않습니다. 키가 다르거나 토큰이 변조되었습니다.'); }
    } else {
      const al = new Uint8Array(8);
      new DataView(al.buffer).setBigUint64(0, BigInt(aad.length * 8));
      const mac = (await DL.fn.hmac(e.hash, cek.slice(0, e.len / 2), concat(aad, iv, ct, al))).slice(0, e.tag);
      if (mac.length !== tag.length || mac.some((v, i) => v !== tag[i])) throw new Error('복호화 실패 — 인증 태그(HMAC)가 맞지 않습니다. 키가 다르거나 토큰이 변조되었습니다.');
      pt = DL.fn.blockCrypt(DL.fn.AES, cek.slice(e.len / 2), iv, ct, { mode: 'cbc', padding: 'pkcs7' }, true);
    }
    if (header.zip === 'DEF') pt = (await DL.fn.decompress(pt, 'raw')).out;
    let body = utf8Decode(pt);
    let note = '';
    try { body = JSON.stringify(JSON.parse(body), null, 2); } catch { if (/^eyJ[\w-]+\.eyJ/.test(body)) note = '\n// 내용이 JWT입니다 (서명된 토큰을 암호화한 중첩 JWT) — JWT 디코더로 이어서 확인하세요.'; }
    return `✓ 복호화 성공 (alg ${alg} · enc ${enc})\n\n${head}\n// Payload\n${body}${note}`;
  }

  /* ---------- HS* 서명키 사전 공격 (HMAC 비밀키 복구) ---------- */
  // 튜토리얼·라이브러리 기본값과 흔한 약한 키. 실습용 토큰은 대부분 여기서 걸린다.
  const COMMON_SECRETS = ['', 'secret', 'your-256-bit-secret', 'your-384-bit-secret', 'your-512-bit-secret', 'secretkey',
    'secret123', 'password', 'password123', 'changeme', 'admin', 'administrator', 'root', 'toor', 'key', 'jwt', 'jwtsecret',
    'jwt-secret', 'mysecret', 'my-secret', 'my-secret-key', 'supersecret', 'super-secret', 's3cr3t', 'topsecret', 'test',
    'testing', 'dev', 'development', 'production', 'staging', 'default', 'example', 'demo', 'qwerty', '123456', '12345678',
    '1234567890', 'letmein', 'welcome', 'access', 'token', 'signature', 'hmac', 'shhhh', 'secretpassword', 'P@ssw0rd', 'HS256'];
  const SUFFIXES = ['', '1', '12', '123', '1234', '12345', '!', '!!', '123!', '@', '#', '$', '_', '2022', '2023', '2024', '2025', '01', '00', '007', '69', '420', '2020'];
  function mangle(word) {
    const out = [];
    const bases = word ? [...new Set([word, word.toLowerCase(), word.toUpperCase(), word.charAt(0).toUpperCase() + word.slice(1)])] : [''];
    for (const b of bases) for (const s of SUFFIXES) out.push(b + s);
    return out;
  }
  const CHARSETS = { lower: 'abcdefghijklmnopqrstuvwxyz', alnum: 'abcdefghijklmnopqrstuvwxyz0123456789', digits: '0123456789', loweralpha: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' };
  function jwtCrack(token, o) {
    const parts = token.trim().split('.');
    if (parts.length !== 3) throw new Error('header.payload.signature 형식의 JWT여야 합니다.');
    let header;
    try { header = JSON.parse(utf8Decode(b64decode(parts[0]), true)); } catch { throw new Error('헤더를 해석할 수 없습니다.'); }
    const alg = String(header.alg || '').toUpperCase();
    const variant = { HS256: 256, HS384: 384, HS512: 512 }[alg];
    if (!variant) throw new Error(`HMAC 기반 토큰(HS256/384/512)만 지원합니다. 이 토큰의 alg는 "${header.alg || '없음'}"입니다. RS/ES/EdDSA는 공개키 암호라 사전 공격 대상이 아닙니다.`);
    const input = utf8(`${parts[0]}.${parts[1]}`);
    const target = b64decode(parts[2]);
    if (!target.length) throw new Error('서명(세 번째 부분)이 비어 있습니다.');
    const hit = (secret) => { const sig = DL.hmacSync(variant, utf8(secret), input); return sig.length === target.length && sig.every((v, i) => v === target[i]); };

    const LIMIT = 3000000; // 브라우저가 멈추지 않도록 시도 상한
    let tried = 0;
    const seen = new Set();
    const found = (secret) => `✓ 서명키를 찾았습니다! (${tried.toLocaleString()}개 시도 · alg ${alg})\n\n키: ${secret === '' ? '(빈 문자열)' : secret}\n길이: ${utf8(secret).length} B\n\n이 키로 토큰을 위조하거나 서명을 변조할 수 있습니다. 실제 서비스라면 32바이트 이상 무작위 키로 즉시 교체하세요.`;
    const tryAll = (cands) => {
      for (const s of cands) {
        if (seen.has(s)) continue;
        seen.add(s); tried++;
        if (hit(s)) return s;
        if (tried >= LIMIT) throw new Error(`시도 상한(${LIMIT.toLocaleString()}개)에 도달했습니다. 범위를 좁히거나, 큰 사전은 아래 hashcat을 쓰세요.`);
      }
      return null;
    };

    const words = [];
    if (o.useCommon !== false) words.push(...COMMON_SECRETS);
    for (const line of (o.wordlist || '').split('\n')) { const w = line.replace(/\r$/, ''); if (w !== '' || !words.includes('')) words.push(w); }
    for (const w of words) { const r = tryAll(o.mangle ? mangle(w) : [w]); if (r !== null) return found(r); }

    if (o.brute) {
      const charset = CHARSETS[o.charset] || CHARSETS.lower;
      const maxLen = Math.min(Math.max(1, Number(o.maxLen) || 4), 6);
      for (let L = 1; L <= maxLen; L++) {
        const idx = new Array(L).fill(0);
        for (;;) {
          let s = ''; for (let i = 0; i < L; i++) s += charset[idx[i]];
          seen.add(s); tried++;
          if (hit(s)) return found(s);
          if (tried >= LIMIT) throw new Error(`시도 상한(${LIMIT.toLocaleString()}개, 길이 ${L}까지)에 도달했습니다. 더 긴 키는 hashcat을 쓰세요.`);
          let p = L - 1; while (p >= 0) { if (++idx[p] < charset.length) break; idx[p] = 0; p--; }
          if (p < 0) break;
        }
      }
    }
    return `✗ ${tried.toLocaleString()}개 후보에서 찾지 못했습니다. (alg ${alg})\n\n키가 사전에 없거나, 무작위로 생성된 강한 키일 수 있습니다. 더 큰 사전(rockyou 등)이나 본격적인 무차별 대입은 GPU 기반 오프라인 도구가 훨씬 빠릅니다:\n\n  hashcat -a 0 -m 16500 token.txt wordlist.txt      # 사전\n  hashcat -a 3 -m 16500 token.txt ?l?l?l?l?l?l       # 소문자 6자 무차별\n  john --format=HMAC-SHA${variant === 256 ? '256' : variant} token.txt    # John the Ripper\n\n(-m 16500 = JWT HS256/384/512)\n\n32바이트 이상 무작위 키는 사실상 복구할 수 없습니다 — 이 경우 키를 발급한 설정 파일·환경 변수·시크릿 매니저에서 직접 찾는 편이 빠릅니다.`;
  }

  Object.assign(DL.fn, { jwtCrack, jweDecrypt, jwtDecode, jwtVerify, jwtSign, asn1Tree, x509Report, jwkToPem, pemToJwk, samlDecode, OIDS });

  const KEY_TEXTAREA = { id: 'key', label: '키', type: 'textarea', default: '', wide: true, placeholder: 'HS*: 비밀키 문자열 · RS/PS/ES/EdDSA: PEM 또는 JWK' };

  DL.addCategory({
    id: 'token',
    name: '웹 토큰·인증서',
    desc: 'JWT 분석·서명 검증부터 JWK, PEM·DER·ASN.1, X.509 인증서, SAML까지 — 웹 인증 데이터 해부',
    color: 'pink',
    tools: [
      {
        id: 'jwt', name: 'JWT 디코더', short: 'Header · Payload · 만료 확인',
        desc: 'JSON Web Token의 헤더와 페이로드를 풀어 보여주고, exp/iat 시간과 alg:none 같은 위험 신호를 표시합니다. 서명 검증은 "JWT 서명 검증·생성"에서 할 수 있습니다.',
        modes: [{ id: 'run', label: '디코딩', inLabel: 'JWT', outLabel: '디코딩 결과', placeholder: 'eyJhbGciOi…' }],
        run: (s) => (s.trim() ? jwtDecode(s) : ''),
      },
      {
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
      },
      {
        id: 'jwtcrack', name: 'JWT 서명키 찾기', short: 'HS256/384/512 비밀키 사전 공격',
        desc: '본인 소유·실습용 HS* 토큰의 잊어버린 비밀키를 찾습니다. 내장 약한 키 목록과 변형, 직접 넣은 단어 목록, 선택적 짧은 무차별 대입으로 서명이 맞는 키를 탐색합니다. 모든 계산은 브라우저 안에서만 이루어지며, 강한 무작위 키는 복구되지 않습니다. 남의 토큰 키를 알아내는 용도로 쓰지 마세요.',
        slow: true,
        modes: [{ id: 'run', label: '키 찾기', inLabel: 'JWT (HS256/384/512)', outLabel: '결과', placeholder: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.…' }],
        options: [
          { id: 'useCommon', label: '내장 약한 키 목록 사용', type: 'checkbox', default: true },
          { id: 'mangle', label: '변형 추가 (대소문자·숫자·기호 붙이기)', type: 'checkbox', default: true },
          { id: 'wordlist', label: '단어 목록 (한 줄에 하나)', type: 'textarea', default: '', wide: true, placeholder: '후보 키를 한 줄에 하나씩 붙여 넣으세요 (선택)' },
          { id: 'brute', label: '짧은 무차별 대입도 시도', type: 'checkbox', default: false },
          { id: 'charset', label: '문자셋', type: 'select', default: 'lower', when: (o) => o.brute, choices: [['lower', '소문자 (a–z)'], ['digits', '숫자 (0–9)'], ['alnum', '소문자+숫자'], ['loweralpha', '대소문자']] },
          { id: 'maxLen', label: '최대 길이', type: 'number', default: 4, min: 1, max: 6, when: (o) => o.brute },
        ],
        run: (s, o) => (s.trim() ? jwtCrack(s, o) : ''),
      },
      {
        id: 'jwe', name: 'JWE 복호화', short: '암호화된 JWT · dir · RSA-OAEP · AES-KW',
        desc: '점이 4개인 암호화된 토큰(JWE)을 복호화합니다. 키 관리 방식 dir·RSA-OAEP(-256)·A128/192/256KW와 콘텐츠 암호화 A*GCM·A*CBC-HS*를 지원하며, 키 없이 넣으면 헤더만 보여줍니다.',
        slow: true,
        modes: [{ id: 'run', label: '복호화', inLabel: 'JWE', outLabel: '복호화 결과', placeholder: 'eyJhbGciOiJSU0EtT0FFUC0yNTYi… (5개 부분)' }],
        options: [
          { id: 'key', label: '키', type: 'textarea', default: '', wide: true, placeholder: 'RSA: 개인키 PEM/JWK · dir/AES-KW: 대칭키 또는 {"kty":"oct","k":"…"}' },
          { id: 'keyFmt', label: '대칭키 형식', type: 'select', default: 'base64', choices: [['base64', 'Base64 / Base64URL'], ['hex', '16진수'], ['text', '텍스트']] },
        ],
        run: (s, o) => jweDecrypt(s, o),
      },
      {
        id: 'jwk', name: 'JWK ↔ PEM', short: 'JSON Web Key · JWKS · 지문',
        desc: 'JWK/JWKS(키 세트)를 PEM으로, PEM을 JWK로 바꿉니다. RFC 7638 지문(thumbprint)도 계산해 kid 확인에 쓸 수 있습니다.',
        slow: true,
        modes: [
          { id: 'decode', label: 'JWK → PEM', inLabel: 'JWK / JWKS', outLabel: 'PEM', placeholder: '{"kty":"EC","crv":"P-256","x":"…","y":"…"}' },
          { id: 'encode', label: 'PEM → JWK', inLabel: 'PEM', outLabel: 'JWK', placeholder: '-----BEGIN PUBLIC KEY----- …' },
        ],
        decode: (s) => jwkToPem(s),
        encode: (s) => pemToJwk(s),
      },
      {
        id: 'asn1', name: 'PEM · DER · ASN.1 뷰어', short: '키·인증서 구조 트리',
        desc: 'PEM이나 DER을 ASN.1 구조 트리로 풀어 보여줍니다. 각 줄 앞의 숫자는 바이트 오프셋이며, OID는 이름으로 표시합니다. 인증서, 키, CSR, PKCS#7 등 모든 DER 데이터에 쓸 수 있습니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '해석', inLabel: 'PEM / DER', outLabel: 'ASN.1 트리', placeholder: '-----BEGIN … ----- 또는 Base64/16진수 DER' }],
        options: [fmtOption('inFmt', 'DER 입력 형식', 'base64', ['base64', 'hex'])],
        run: (s, o) => {
          const { label, der } = readDer(s, o.inFmt);
          return `${label} · ${der.length.toLocaleString()} B\n\n${asn1Tree(asn1Parse(der)).join('\n')}`;
        },
      },
      {
        id: 'x509', name: 'X.509 인증서', short: '주체·발급자·유효기간·SAN',
        desc: 'TLS 인증서를 사람이 읽기 쉽게 요약합니다. 주체·발급자, 유효 기간과 만료 여부, 공개키, SAN(도메인 목록), 용도, 지문을 보여줍니다.',
        fileInput: true, slow: true,
        modes: [{ id: 'run', label: '분석', inLabel: '인증서', outLabel: '인증서 정보', placeholder: '-----BEGIN CERTIFICATE----- …' }],
        options: [fmtOption('inFmt', 'DER 입력 형식', 'base64', ['base64', 'hex'])],
        run: (s, o) => x509Report(readDer(s, o.inFmt).der),
      },
      {
        id: 'saml', name: 'SAML 디코더', short: 'SAMLRequest · SAMLResponse',
        desc: 'SSO에 쓰이는 SAML 메시지를 디코딩합니다. URL 전체, 파라미터 값, Base64만 넣어도 되며 HTTP-Redirect 바인딩의 DEFLATE 압축도 자동으로 풉니다.',
        slow: true,
        modes: [{ id: 'run', label: '디코딩', inLabel: 'SAML 메시지', outLabel: 'XML' }],
        run: (s) => samlDecode(s),
      },
    ],
    planned: [['JWE ECDH-ES · PBES2', '추가 키 관리 방식']],
  });
})(globalThis.DecryptLab);
