/* 자동 분석 */
(function (DL) {
  'use strict';
  const { utf8, utf8Decode, b64decode, fromHex, printableScore, textScore, toHex, fn } = DL;

  function autoDetect(input, raw = false) {
    const s = input.trim();
    if (!s) return raw ? [] : '';
    const asText = (b) => utf8Decode(b);
    const candidates = [
      ['Base64', /^[A-Za-z0-9+/\s]+={0,2}$/, () => asText(b64decode(s))],
      ['Base64 URL-safe', /^[A-Za-z0-9_\-\s]+={0,2}$/, () => asText(b64decode(s))],
      ['Base32', /^[A-Z2-7\s]+=*$/i, () => asText(fn.b32decode(s))],
      ['Base58', /^[1-9A-HJ-NP-Za-km-z]+$/, () => asText(fn.b58decode(s))],
      ['Ascii85', /^<~[\s\S]*~>$/, () => asText(fn.a85decode(s))],
      ['16진수(Hex)', /^((0x|\\x)?[0-9a-f]{2}[\s:,]*)+$/i, () => asText(fromHex(s))],
      ['2진수', /^[01\s]+$/, () => asText(fn.radixDecode(s, 2))],
      ['10진수 바이트', /^\d{1,3}([\s,]+\d{1,3})+$/, () => asText(fn.radixDecode(s, 10))],
      ['URL 인코딩', /%[0-9a-f]{2}/i, () => asText(fn.urlDecode(s, { plus: true }))],
      ['HTML 엔티티', /&(#x?[0-9a-f]+|[a-z]+);/i, () => fn.htmlDecode(s)],
      ['유니코드 이스케이프', /\\u[0-9a-f{]|U\+[0-9a-f]{4}/i, () => fn.uniDecode(s)],
      ['JS·C 바이트 이스케이프', /\\x[0-9a-f]{2}/i, () => asText(fn.jsUnescape(s, { xmode: 'byte' }))],
      ['Quoted-Printable', /=[0-9A-F]{2}/, () => asText(fn.qpDecode(s))],
      ['MIME Encoded-Word', /=\?[^?]+\?[BQ]\?/i, () => fn.mimeWordDecode(s)],
      ['Punycode 도메인', /(^|\.)xn--/i, () => fn.idnToUnicode(s)],
      ['모스 부호', /^[.\-·_\s/|]+$/, () => fn.morseDecode(s)],
      ['JWT', /^eyJ[\w-]*\.eyJ[\w-]*\.?[\w-]*$/, () => fn.jwtDecode(s)],
      ['ROT13', /[A-Za-z]/, () => fn.caesar(s, 13)],
      ['Atbash', /[A-Za-z]/, () => fn.atbash(s)],
    ];
    const results = [];
    for (const [name, re, f] of candidates) {
      if (!re.test(s)) continue;
      try {
        const out = f();
        if (!out || out === s || results.some((r) => r.out === out)) continue;
        let score = printableScore(out);
        if (name === 'ROT13' || name === 'Atbash') score *= 0.5; // 항상 성공하므로 가중치 낮춤
        if (score < 0.6) continue;
        results.push({ name, out, score });
      } catch { /* 해당 형식이 아님 */ }
    }
    const hints = [];
    if (/^U2FsdGVkX1/.test(s)) hints.push('"U2FsdGVkX1"로 시작합니다 — OpenSSL/CryptoJS 비밀번호 암호화 형식입니다. → 대칭키 암호 › OpenSSL · CryptoJS 호환');
    if (/^[0-9a-f]+$/i.test(s) && [32, 40, 64, 96, 128].includes(s.length)) {
      const names = { 32: 'MD5 (또는 NTLM·MD4)', 40: 'SHA-1 (또는 RIPEMD-160)', 64: 'SHA-256 (또는 SHA3-256·BLAKE2s)', 96: 'SHA-384', 128: 'SHA-512 (또는 SHA3-512·Whirlpool)' };
      hints.push(`16진수 ${s.length}자 — ${names[s.length]} 해시일 수 있습니다. 해시는 복호화할 수 없으며 형식만으로 확정할 수도 없습니다.`);
    }
    if (/^\$2[aby]\$\d\d\$/.test(s)) hints.push('bcrypt 비밀번호 해시 형식입니다. 복호화할 수 없고 후보 비밀번호로 검증만 가능합니다.');
    if (/^\$argon2(id|i|d)\$/.test(s)) hints.push('Argon2 비밀번호 해시 형식입니다.');
    if (/^-----BEGIN /.test(s)) hints.push('PEM 형식(키 또는 인증서)입니다. → 공개키 암호·서명');

    if (raw) return results.sort((a, b) => b.score - a.score);
    const parts = [];
    if (hints.length) parts.push('■ 형식 힌트\n' + hints.map((h) => `  · ${h}`).join('\n'));
    if (results.length) {
      results.sort((a, b) => b.score - a.score);
      parts.push(results.map((r, i) => {
        const preview = r.out.length > 600 ? r.out.slice(0, 600) + ' …' : r.out;
        return `[${i + 1}] ${r.name}  — 가독성 ${(r.score * 100).toFixed(0)}%\n${preview}`;
      }).join('\n\n────────────────────\n\n'));
    }
    if (!parts.length) return '알려진 인코딩 형식을 찾지 못했습니다.\n입력이 이미 평문이거나, 키가 필요한 암호문일 수 있습니다.';
    parts.push('※ 후보 추정 결과입니다. 형식이 맞아 보여도 실제 인코딩과 다를 수 있습니다.');
    return parts.join('\n\n');
  }

  /* ---------- 해시 식별 ---------- */
  const HEX_LEN = {
    8: ['CRC32', 'Adler-32', 'FNV-1a 32비트'], 16: ['CRC64', 'FNV-1a 64비트', 'MySQL 3.x (OLD_PASSWORD)'],
    32: ['MD5', 'NTLM', 'MD4', 'LM'], 40: ['SHA-1', 'RIPEMD-160'], 56: ['SHA-224', 'SHA3-224'],
    64: ['SHA-256', 'SHA3-256', 'Keccak-256 (이더리움)', 'BLAKE2s-256', 'BLAKE3'], 96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'],
  };
  const PATTERNS = [
    [/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt', '비용(cost) 값이 $ 사이 두 자리 숫자입니다.'],
    [/^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$/, 'Argon2', '메모리(m)·반복(t)·병렬(p) 매개변수가 포함되어 있습니다.'],
    [/^\$1\$[^$]{0,8}\$[./A-Za-z0-9]{22}$/, 'MD5-crypt (Unix /etc/shadow)'],
    [/^\$apr1\$[^$]{0,8}\$[./A-Za-z0-9]{22}$/, 'Apache APR1-MD5 (htpasswd)'],
    [/^\$5\$(rounds=\d+\$)?[^$]{0,16}\$[./A-Za-z0-9]{43}$/, 'SHA-256-crypt (Unix /etc/shadow)'],
    [/^\$6\$(rounds=\d+\$)?[^$]{0,16}\$[./A-Za-z0-9]{86}$/, 'SHA-512-crypt (Unix /etc/shadow)'],
    [/^\$y\$/, 'yescrypt (최신 Linux /etc/shadow)'], [/^\$7\$/, 'scrypt (crypt 형식)'],
    [/^\$[PH]\$[./A-Za-z0-9]{31}$/, 'phpass (WordPress·phpBB)'], [/^\$S\$[./A-Za-z0-9]{52}$/, 'Drupal 7 SHA-512'],
    [/^pbkdf2_sha256\$\d+\$/, 'Django PBKDF2-SHA256'], [/^pbkdf2_sha1\$\d+\$/, 'Django PBKDF2-SHA1'],
    [/^\$pbkdf2(-sha\d+)?\$\d+\$/, 'PBKDF2 (passlib 형식)'], [/^scrypt:\d+:\d+:\d+\$/, 'Werkzeug scrypt'], [/^pbkdf2:sha\d+:\d+\$/, 'Werkzeug PBKDF2'],
    [/^\*[0-9A-F]{40}$/i, 'MySQL 4.1+ (SHA1(SHA1(비밀번호)))'], [/^0x0100[0-9a-f]{48}$/i, 'MSSQL 2005'], [/^0x0200[0-9a-f]{136}$/i, 'MSSQL 2012+'],
    [/^\{SSHA\}/i, 'LDAP 솔트 SHA-1'], [/^\{SHA\}/i, 'LDAP SHA-1'], [/^\{SSHA512\}/i, 'LDAP 솔트 SHA-512'], [/^\{MD5\}/i, 'LDAP MD5'],
    [/^[^:]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$/i, 'NetNTLMv2 (네트워크 인증 응답)'],
    [/^[^:]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$/i, 'NetNTLMv1'],
    [/^\$krb5tgs\$/, 'Kerberos TGS 티켓'], [/^\$krb5asrep\$/, 'Kerberos AS-REP'],
    [/^[A-Za-z0-9+/]{27}=$/, 'Base64로 인코딩된 SHA-1 (20 B)'], [/^[A-Za-z0-9+/]{22}==$/, 'Base64로 인코딩된 MD5 (16 B)'],
    [/^[A-Za-z0-9+/]{43}=$/, 'Base64로 인코딩된 SHA-256 (32 B)'], [/^[A-Za-z0-9+/]{86}==$/, 'Base64로 인코딩된 SHA-512 (64 B)'],
  ];
  function identifyHash(input) {
    const lines = input.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    return lines.map((h) => {
      const found = [];
      for (const [re, name, note] of PATTERNS) if (re.test(h)) found.push(note ? `${name} — ${note}` : name);
      const hex = h.replace(/^0x/i, '');
      if (!found.length && /^[0-9a-f]+$/i.test(hex) && HEX_LEN[hex.length]) {
        found.push(...HEX_LEN[hex.length]);
        if (hex.length === 32 && hex === hex.toUpperCase() && /[A-F]/.test(hex)) found.push('(대문자 16진수 — Windows NTLM·LM 덤프에서 흔함)');
      }
      const body = found.length ? found.map((f, i) => `  ${i === 0 ? '가장 유력' : '가능    '}  ${f}`).join('\n')
        : `  알려진 해시 형식이 아닙니다. (${/^[0-9a-f]+$/i.test(hex) ? `16진수 ${hex.length}자` : `${h.length}자`})`;
      return `■ ${h.length > 70 ? h.slice(0, 70) + '…' : h}\n${body}`;
    }).join('\n\n') + '\n\n※ 형식만 보고 추정한 결과입니다. 같은 길이의 다른 데이터일 수 있으며, 해시는 복호화할 수 없습니다.';
  }

  /* ---------- 재귀 디코더 ---------- */
  // 각 단계: 현재 바이트를 텍스트로 보고 디코더를 모두 시도한 뒤, 가장 읽기 좋은 결과 하나를 채택한다.
  const STEPS = [
    ['Gzip/Zlib 해제', (t, b) => (b[0] === 0x1f && b[1] === 0x8b) || (((b[0] & 0x0f) === 8) && ((b[0] << 8) | b[1]) % 31 === 0 && b.length > 2), async (t, b) => (await fn.decompress(b, 'auto')).out, 3],
    ['Base64', (t) => /^[A-Za-z0-9+/_\-\s]+={0,2}$/.test(t) && t.replace(/\s/g, '').length >= 4, (t) => b64decode(t), 2],
    ['16진수(Hex)', (t) => /^((0x|\\x)?[0-9a-f]{2}[\s:,]*)+$/i.test(t), (t) => fromHex(t), 2.5],
    ['Base32', (t) => /^[A-Z2-7\s]+=*$/.test(t) && t.replace(/[\s=]/g, '').length >= 8, (t) => fn.b32decode(t), 1.5],
    ['Base58', (t) => /^[1-9A-HJ-NP-Za-km-z]{6,}$/.test(t), (t) => fn.b58decode(t), 1],
    ['Ascii85', (t) => /^<~[\s\S]*~>$/.test(t), (t) => fn.a85decode(t), 3],
    ['2진수', (t) => /^[01\s]+$/.test(t) && t.replace(/\s/g, '').length % 8 === 0, (t) => fn.radixDecode(t, 2), 3],
    ['10진수 바이트', (t) => /^\d{1,3}([\s,]+\d{1,3})+$/.test(t), (t) => fn.radixDecode(t, 10), 2],
    ['URL 디코딩', (t) => /%[0-9a-f]{2}/i.test(t), (t) => fn.urlDecode(t, { plus: true }), 3],
    ['HTML 엔티티', (t) => /&(#x?[0-9a-f]+|[a-z]+);/i.test(t), (t) => utf8(fn.htmlDecode(t)), 3],
    ['유니코드 이스케이프', (t) => /\\u[0-9a-f{]/i.test(t), (t) => utf8(fn.uniDecode(t)), 3],
    ['\\x 바이트 이스케이프', (t) => /\\x[0-9a-f]{2}/i.test(t), (t) => fn.jsUnescape(t, { xmode: 'byte' }), 3],
    ['Quoted-Printable', (t) => /=[0-9A-F]{2}/.test(t) && !/[^\x20-\x7e\r\n]/.test(t), (t) => fn.qpDecode(t), 1],
  ];
  const isGz = (b) => (b[0] === 0x1f && b[1] === 0x8b);
  async function recursiveDecode(input, { maxDepth = 15 } = {}) {
    let bytes = utf8(input.trim());
    const steps = [];
    const seen = new Set([toHexKey(bytes)]);
    for (let depth = 0; depth < maxDepth; depth++) {
      let text = '';
      try { text = utf8Decode(bytes, true).trim(); } catch { text = ''; }
      let best = null;
      for (const [name, test, decode, prio] of STEPS) {
        if (!test(text, bytes)) continue;
        let out;
        try { out = await decode(text, bytes); } catch { continue; }
        if (!out || !out.length || seen.has(toHexKey(out))) continue;
        const readable = textScore(out);
        const score = isGz(out) ? 0.97 : readable;
        if (score < 0.9) continue;
        const rank = score * 10 + prio;
        if (!best || rank > best.rank) best = { name, out, rank };
      }
      if (!best) break;
      seen.add(toHexKey(best.out));
      steps.push({ name: best.name, out: best.out });
      bytes = best.out;
    }
    if (!steps.length) return '디코딩할 수 있는 인코딩을 찾지 못했습니다. 이미 평문이거나, 키가 필요한 암호문일 수 있습니다.\n→ "인코딩 자동 감지"나 "바이너리 분석 › 엔트로피 분석"으로 확인해 보세요.';
    const preview = (b) => { try { const t = utf8Decode(b, true); return t.length > 160 ? t.slice(0, 160) + ' …' : t; } catch { return `(바이너리 ${b.length} B)`; } };
    const lines = steps.map((s, i) => `${String(i + 1).padStart(2)}. ${s.name.padEnd(14)} → ${preview(s.out).replace(/\n/g, '⏎')}`);
    let final;
    try { final = utf8Decode(bytes, true); } catch { final = DL.toHex(bytes, false, ' '); }
    return `■ 디코딩 경로 (${steps.length}단계): ${steps.map((s) => s.name).join(' → ')}\n\n${lines.join('\n')}\n\n■ 최종 결과\n${final}`;
  }
  const toHexKey = (b) => (b.length > 4096 ? `${b.length}:${DL.toHex(b.subarray(0, 64))}${DL.toHex(b.subarray(-64))}` : DL.toHex(b));

  /* ---------- 종합 분석 리포트 ---------- */
  const toolPath = (c, t) => {
    const cat = DL.CATEGORIES.find((x) => x.id === c);
    const tool = cat && cat.tools.find((x) => x.id === t);
    return tool ? `${cat.name} › ${tool.name}` : null;
  };
  const CONF = { 3: '높음', 2: '중간', 1: '낮음' };
  const COMMON = new Set('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were has had been flag key secret password hello world message text'.split(' '));
  async function analysisReport(input) {
    const s = input.trim();
    if (!s) return '';
    const raw = utf8(s);
    const findings = [];
    const add = (conf, what, why, extra = {}) => findings.push({ conf, what, why, ...extra });

    // 1) 개요
    const isHex = /^((0x|\\x)?[0-9a-f]{2}[\s:,]*)+$/i.test(s);
    const isB64 = /^[A-Za-z0-9+/_\-\s]+={0,2}$/.test(s) && s.replace(/\s/g, '').length % 4 !== 1;
    const letters = (s.match(/[A-Za-z]/g) || []).length;
    const charset = isHex ? '16진수 문자만 (0–9, a–f)' : isB64 ? 'Base64 문자 집합' : /^[\x20-\x7e\r\n\t]+$/.test(s) ? '출력 가능한 ASCII' : '비ASCII 문자 포함 (한글 등)';
    let decoded = null, decodedBy = '';
    try { if (isHex) { decoded = fromHex(s); decodedBy = '16진수'; } else if (isB64) { decoded = b64decode(s); decodedBy = 'Base64'; } } catch { decoded = null; }
    const overview = [`길이        ${Array.from(s).length.toLocaleString()}자 · ${raw.length.toLocaleString()} B`, `문자 구성   ${charset}`, `엔트로피    ${DL.entropy(raw).toFixed(2)} 비트/문자`];
    if (decoded) overview.push(`${decodedBy} 디코딩 시 ${decoded.length.toLocaleString()} B · 엔트로피 ${DL.entropy(decoded).toFixed(2)} 비트/바이트`);

    // 2) 구조적 형식 (확실한 신호)
    if (/^-----BEGIN [A-Z0-9 ]+-----/.test(s)) add(3, 'PEM (키 또는 인증서)', 'BEGIN/END 경계선이 있습니다.', { tools: [toolPath('token', 'x509'), toolPath('token', 'asn1')] });
    const dots = s.split('.');
    if (/^eyJ/.test(s) && dots.length === 3) add(3, 'JWT (서명된 토큰)', 'Base64URL JSON 헤더(eyJ…)와 점 2개로 구성됩니다.', { need: '서명 검증에는 비밀키나 공개키가 필요합니다. 내용 확인에는 키가 필요 없습니다.', tools: [toolPath('token', 'jwt'), toolPath('token', 'jwtverify')] });
    if (/^eyJ/.test(s) && dots.length === 5) add(3, 'JWE (암호화된 토큰)', '점 4개로 나뉜 5개 부분입니다.', { need: '복호화 키(RSA 개인키 또는 대칭키)가 필요합니다.', tools: [toolPath('token', 'jwe')] });
    if (/^U2FsdGVkX1/.test(s)) add(3, 'OpenSSL·CryptoJS 비밀번호 암호문', 'Base64 "Salted__" 헤더(U2FsdGVkX1)로 시작합니다.', { need: '암호화에 쓴 비밀번호가 필요합니다.', tools: [toolPath('symmetric', 'openssl')] });
    if (/^data:[^,]*,/.test(s)) add(3, 'Data URI', 'data: 스킴으로 시작합니다.', { tools: [toolPath('binary', 'datauri')] });
    if (/(SAMLRequest|SAMLResponse)=/.test(s)) add(3, 'SAML 메시지', 'SAML 파라미터가 포함되어 있습니다.', { tools: [toolPath('token', 'saml')] });

    // 3) 해시 형식
    const hashLines = identifyHash(s).split('\n');
    const hashTop = hashLines.find((l) => l.includes('가장 유력'));
    if (hashTop && !s.includes('\n')) {
      const name = hashTop.replace(/.*가장 유력\s+/, '');
      const strong = PATTERNS.some(([re]) => re.test(s));
      add(strong ? 3 : 2, `해시값 — ${name}`, strong ? '해시 형식 고유의 접두사·구조가 있습니다.' : '길이와 문자 구성이 해시와 일치합니다. 같은 길이의 다른 데이터(키, 암호문)일 수도 있습니다.',
        { need: '해시는 복호화할 수 없습니다. 후보 평문을 해시해서 비교하는 방식으로만 확인할 수 있습니다.', tools: [toolPath('auto', 'hashid'), toolPath('hash', 'hash')] });
    }

    // 4) 인코딩 — 재귀 디코더로 끝까지 풀어 본다
    const rec = await recursiveDecode(s);
    const path = /디코딩 경로 \((\d+)단계\): (.*)/.exec(rec);
    if (path) {
      const final = rec.split('■ 최종 결과\n')[1] || '';
      add(Number(path[1]) > 1 ? 3 : 2.5, Number(path[1]) > 1 ? `중첩 인코딩 (${path[1]}겹)` : `인코딩 — ${path[2]}`, `${path[2]} 순서로 풀면 읽을 수 있는 결과가 나옵니다.`,
        { result: final.length > 300 ? final.slice(0, 300) + ' …' : final, tools: [toolPath('auto', 'recursive')] });
    }

    // 5) 디코딩해도 읽을 수 없는 바이너리 → 파일/압축/암호문
    if (decoded && decoded.length && textScore(decoded) < 0.9) {
      const magic = fn.identifyMagic ? fn.identifyMagic(decoded) : [];
      const h = DL.entropy(decoded);
      if (magic.length) add(3, `${decodedBy}로 감싼 파일 — ${magic[0].name}`, `디코딩한 바이트가 ${magic[0].name} 시그니처로 시작합니다.`, { tools: [toolPath('binary', 'magic'), magic[0].ext === 'gz' || magic[0].ext === 'zlib' ? toolPath('compress', 'deflate') : magic[0].ext === 'zip' ? toolPath('compress', 'zip') : toolPath('binary', 'hexview')].filter(Boolean) });
      else if (h > 6.5 || (decoded.length < 256 && h > 4.5)) {
        if (decoded.length % 16 === 0) add(2, '블록 암호문 가능성 (AES·ARIA·SEED 등)', `${decodedBy} 디코딩 결과가 무작위적이고(엔트로피 ${h.toFixed(2)}) 길이 ${decoded.length} B가 16의 배수입니다.`,
          { need: '키, 운용 모드(CBC·GCM 등), IV가 필요합니다. IV가 암호문 앞 16 B에 붙어 있는 경우가 많습니다.', tools: [toolPath('symmetric', 'aes'), toolPath('symmetric', 'aria'), toolPath('symmetric', 'seed')] });
        else add(1.5, '스트림 암호문 또는 XOR 가능성', `무작위적이지만 길이(${decoded.length} B)가 블록 크기의 배수가 아닙니다. RC4·ChaCha20·CTR/GCM 모드·XOR일 수 있습니다.`,
          { need: '키(와 nonce)가 필요합니다.', tools: [toolPath('symmetric', 'rc4'), toolPath('symmetric', 'chacha20'), toolPath('binary', 'xorbrute')] });
      } else if (!xorFinding(decoded)) {
        add(1, '구조가 있는 바이너리', `엔트로피 ${h.toFixed(2)} — 암호문보다는 실행 파일·데이터 파일 일부에 가깝습니다.`, { tools: [toolPath('binary', 'hexview'), toolPath('binary', 'strings')] });
      }
    } else if (decoded && decoded.length >= 8) xorFinding(decoded);

    // 단일 바이트 XOR: 원래 바이트보다 XOR 결과가 훨씬 영어다우면 후보로 올린다
    function xorFinding(bytes) {
      if (!fn.xorBrute) return false;
      const m = /키 0x([0-9a-f]{2}).*점수 (-?[\d.]+)\n([\s\S]*)/.exec(fn.xorBrute(bytes, { top: 1 }));
      if (!m || m[1] === '00' || Number(m[2]) < 1.2 || Number(m[2]) < fn.englishScore(bytes) + 0.8) return false;
      add(2.8, `단일 바이트 XOR (키 0x${m[1]})`, `${decodedBy} 디코딩 결과를 한 바이트 키 0x${m[1]}로 XOR하면 영어 문장에 가까워집니다.`, { result: m[3].slice(0, 200), tools: [toolPath('binary', 'xorbrute')] });
      return true;
    }

    // 6) 영문자 위주 → 고전 암호
    if (!findings.some((f) => f.conf >= 2.5) && letters >= 20 && letters / s.replace(/\s/g, '').length > 0.85) {
      const ic = fn.ioc(s);
      const { shift } = fn.bestShift(s);
      const words = (t) => (t.toLowerCase().match(/[a-z]+/g) || []).filter((w) => COMMON.has(w)).length;
      const shifted = fn.caesar(s, -shift);
      if (shift && words(shifted) >= 2 && words(shifted) > words(s)) {
        add(2.8, `카이사르 암호 (시프트 ${shift})`, `${shift}칸 되돌리면 흔한 영어 단어가 ${words(shifted)}개 나타납니다.`, { result: shifted.slice(0, 200), tools: [toolPath('classic', 'caesar')] });
      } else if (ic > 0.058) {
        const { shift } = fn.bestShift(s);
        add(shift ? 2 : 1, shift ? `카이사르 암호 (시프트 ${shift}) 가능성` : '평문 영어 또는 전치 암호', `일치 지수(IC) ${ic.toFixed(3)}가 영어(≈0.066)에 가깝습니다 — 단일 치환이나 전치 암호의 특징입니다.`,
          { result: shift ? fn.caesar(s, -shift).slice(0, 200) : undefined, tools: [toolPath('classic', 'analyze'), toolPath('classic', 'caesar')] });
      } else if (ic < 0.05) add(1.5, '다중 치환 암호 (비즈네르 계열) 가능성', `일치 지수(IC) ${ic.toFixed(3)}가 낮습니다 — 키워드를 쓰는 다중 치환 암호의 특징입니다.`,
        { need: '키워드가 필요합니다. 빈도 분석 도구로 키 길이와 키를 추정해 볼 수 있습니다.', tools: [toolPath('classic', 'analyze'), toolPath('classic', 'vigenere')] });
    }

    // 7) 그 밖의 디코딩 후보
    const cands = autoDetect(s, true).filter((c) => !findings.some((f) => f.result && f.result.startsWith(c.out.slice(0, 50))));
    if (!findings.length && !cands.length) add(1, '판별 불가', '알려진 인코딩·형식과 일치하지 않습니다. 평문이거나, 키가 필요한 암호문이거나, 이 도구가 지원하지 않는 형식일 수 있습니다.', { tools: [toolPath('binary', 'entropy')] });

    findings.sort((a, b) => b.conf - a.conf);
    const out = ['■ 데이터 개요', ...overview.map((l) => '  ' + l), '', '■ 유형 추정 (신뢰도순)'];
    findings.forEach((f, i) => {
      out.push(`  ${i + 1}. [${CONF[Math.round(f.conf)] || '낮음'}] ${f.what}`, `     근거  ${f.why}`);
      if (f.need) out.push(`     필요  ${f.need}`);
      if (f.result) out.push(`     결과  ${f.result.replace(/\n/g, '\n           ')}`);
      if (f.tools && f.tools.filter(Boolean).length) out.push(`     도구  ${f.tools.filter(Boolean).join('  ·  ')}`);
      out.push('');
    });
    if (cands.length) {
      out.push('■ 기타 디코딩 후보');
      cands.slice(0, 3).forEach((c) => out.push(`  · ${c.name} (가독성 ${(c.score * 100).toFixed(0)}%)  ${c.out.slice(0, 120).replace(/\n/g, '⏎')}`));
      out.push('');
    }
    out.push('※ 형식과 통계로 추정한 결과입니다. "높음"도 확정이 아니며, 실제 알고리즘·키는 출처 정보와 함께 판단하세요.');
    return out.join('\n');
  }

  DL.fn.analysisReport = analysisReport;
  DL.fn.autoDetect = autoDetect;
  DL.fn.recursiveDecode = recursiveDecode;
  DL.fn.identifyHash = identifyHash;

  DL.addCategory({
    id: 'auto',
    name: '자동 분석',
    desc: '정체 모를 문자열을 넣으면 가능한 인코딩·암호·해시 후보와 디코딩 결과를 한 번에 보여줍니다',
    color: 'lime',
    tools: [
      {
        id: 'report', name: '종합 분석 리포트', short: '유형 추정 · 후보 · 필요한 키 · 다음 단계',
        desc: '정체 모를 값을 넣으면 데이터 특성(문자 구성, 엔트로피), 가능한 형식과 신뢰도, 디코딩 결과, 복호화에 필요한 키·파라미터, 이어서 쓸 도구를 한 번에 정리합니다.',
        slow: true,
        modes: [{ id: 'run', label: '분석', inLabel: '분석할 값', outLabel: '분석 리포트' }],
        run: (s) => analysisReport(s),
      },
      {
        id: 'detect', name: '인코딩 자동 감지', short: '여러 디코더를 한 번에 시도',
        desc: '입력을 알려진 형식으로 모두 디코딩해 보고, 읽을 수 있는 결과가 나온 순서대로 보여줍니다. 해시·OpenSSL 암호문·PEM 같은 형식 힌트도 함께 표시합니다. 결과는 후보 추정이지 확정이 아닙니다.',
        modes: [{ id: 'run', label: '분석', inLabel: '분석할 값', outLabel: '후보' }],
        run: (s) => autoDetect(s),
      },
      {
        id: 'recursive', name: '재귀 디코더', short: '중첩된 인코딩을 끝까지 자동 해제',
        desc: 'Base64 → Hex → URL 인코딩 → Gzip처럼 여러 겹으로 감싼 데이터를 읽을 수 있는 결과가 나올 때까지 반복해서 풉니다. 각 단계에서 가장 읽기 좋은 결과를 고르며, 거쳐 간 경로를 함께 보여줍니다.',
        slow: true,
        modes: [{ id: 'run', label: '자동 해제', inLabel: '인코딩된 값', outLabel: '디코딩 경로와 결과' }],
        options: [{ id: 'maxDepth', label: '최대 단계', type: 'number', default: 15, min: 1, max: 50 }],
        run: (s, o) => recursiveDecode(s, { maxDepth: Math.min(50, Number(o.maxDepth) || 15) }),
      },
      {
        id: 'hashid', name: '해시 식별기', short: '길이·패턴으로 해시 종류 추정',
        desc: '해시 문자열의 길이, 문자 구성, 접두사($2b$, $6$ 등)로 어떤 알고리즘인지 추정합니다. 여러 줄을 한 번에 넣을 수 있습니다. 해시는 복호화가 아니라 같은 값인지 비교하는 용도입니다.',
        modes: [{ id: 'run', label: '식별', inLabel: '해시 (한 줄에 하나)', outLabel: '후보' }],
        run: (s) => identifyHash(s),
      },
    ],
    planned: [],
  });
})(globalThis.DecryptLab);
