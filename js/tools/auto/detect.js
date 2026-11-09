/* 자동 분석 › 인코딩 자동 감지 (양방향) */
(function (DL) {
  'use strict';
  const K = DL.kits.auto;
  const { utf8, utf8Decode, b64decode, b64encode, fromHex, printableScore, toHex, fn } = K;

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
  K.autoDetect = autoDetect;
  DL.fn.autoDetect = autoDetect;

  /* ---------- 양방향 변환용 형식 레지스트리 ---------- */
  const U = (b) => utf8Decode(b, true); // 바이트 → 텍스트(비텍스트면 예외로 후보 탈락)
  const FORMATS = [
    { id: 'base64', label: 'Base64', dec: (s) => U(b64decode(s)), enc: (p) => b64encode(utf8(p)) },
    { id: 'base64url', label: 'Base64 URL-safe', dec: (s) => U(b64decode(s)), enc: (p) => b64encode(utf8(p), { urlsafe: true, nopad: true }) },
    { id: 'base32', label: 'Base32', dec: (s) => U(fn.b32decode(s)), enc: (p) => fn.b32encode(utf8(p)) },
    { id: 'base58', label: 'Base58', dec: (s) => U(fn.b58decode(s)), enc: (p) => fn.b58encode(utf8(p)) },
    { id: 'ascii85', label: 'Ascii85', dec: (s) => U(fn.a85decode(s)), enc: (p) => fn.a85encode(utf8(p)) },
    { id: 'hex', label: '16진수(Hex)', dec: (s) => U(fromHex(s)), enc: (p) => toHex(utf8(p), false, ' ') },
    { id: 'binary', label: '2진수', dec: (s) => U(fn.radixDecode(s, 2)), enc: (p) => Array.from(utf8(p)).map((b) => b.toString(2).padStart(8, '0')).join(' ') },
    { id: 'decimal', label: '10진수 바이트', dec: (s) => U(fn.radixDecode(s, 10)), enc: (p) => Array.from(utf8(p)).join(' ') },
    { id: 'url', label: 'URL 인코딩', dec: (s) => U(fn.urlDecode(s, { plus: true })), enc: (p) => fn.urlEncode(p) },
    { id: 'html', label: 'HTML 엔티티', dec: (s) => fn.htmlDecode(s), enc: (p) => fn.htmlEncode(p) },
    { id: 'unicode', label: '유니코드 이스케이프', dec: (s) => fn.uniDecode(s), enc: (p) => fn.uniEncode(p) },
    { id: 'qp', label: 'Quoted-Printable', dec: (s) => U(fn.qpDecode(s)), enc: (p) => fn.qpEncode(p) },
  ];
  const FMT_BY_ID = Object.fromEntries(FORMATS.map((f) => [f.id, f]));
  const FMT_BY_NAME = Object.fromEntries(FORMATS.map((f) => [f.label, f])); // autoDetect 표시 이름 → 형식
  let lastDetected = 'base64'; // '자동 감지'로 디코딩했을 때 마지막으로 감지한 형식 (재인코딩에 사용)

  function detectDecode(s, o) {
    const v = (s || '').trim();
    if (!v) return { text: '', note: '값을 넣으면 평문이 나오고, 평문을 고치면 그 형식으로 다시 인코딩됩니다.' };
    if (o.format && o.format !== 'auto') {
      const f = FMT_BY_ID[o.format];
      lastDetected = f.id;
      return { text: f.dec(v), note: `형식: ${f.label}`, cls: 'ok' };
    }
    const results = autoDetect(v, true); // 점수순 [{name, out, score}]
    if (!results.length) return { text: '', note: '알려진 인코딩 형식을 찾지 못했습니다. 이미 평문이거나 키가 필요한 암호문일 수 있습니다.', cls: 'warn' };
    const best = results[0];
    const mapped = FMT_BY_NAME[best.name];
    lastDetected = mapped ? mapped.id : null;
    const others = results.slice(1, 4).map((r) => r.name).join(', ');
    const tail = mapped ? '' : ' · 이 형식은 재인코딩을 지원하지 않습니다';
    return { text: best.out, note: `감지: ${best.name} (가독성 ${Math.round(best.score * 100)}%)${others ? ' · 다른 후보: ' + others : ''}${tail}`, cls: 'ok' };
  }
  function detectEncode(p, o) {
    if (p == null || p === '') return { text: '', note: '평문을 넣으면 선택한 형식으로 인코딩됩니다.' };
    const id = o.format && o.format !== 'auto' ? o.format : lastDetected;
    const f = id && FMT_BY_ID[id];
    if (!f) return { text: '', note: '재인코딩할 형식을 알 수 없습니다. 형식을 직접 골라 주세요.', cls: 'warn' };
    return { text: f.enc(p), note: `형식: ${f.label}`, cls: 'ok' };
  }

  DL.addTool('auto', {
    id: 'detect', name: '인코딩 자동 감지', short: '값↔평문 양방향 · 형식 자동 감지',
    desc: '값을 넣으면 형식을 자동 감지해 평문으로 풀고, 감지된 형식은 결과 아래에 표시합니다. 평문 쪽을 고치면 같은 형식으로 다시 인코딩합니다. 형식을 직접 고를 수도 있습니다. 여러 형식을 한 번에 비교하려면 "종합 분석 리포트"를 쓰세요.',
    modes: [
      { id: 'decode', label: '디코딩', inLabel: '값', outLabel: '평문', placeholder: 'Base64·Hex·URL 인코딩 등 아무 값이나 붙여넣으세요' },
      { id: 'encode', label: '인코딩', inLabel: '평문', outLabel: '값' },
    ],
    options: [
      { id: 'format', label: '형식', type: 'select', default: 'auto', choices: [['auto', '자동 감지'], ...FORMATS.map((f) => [f.id, f.label])] },
    ],
    decode: (s, o) => detectDecode(s, o),
    encode: (p, o) => detectEncode(p, o),
  });
})(globalThis.DecryptLab);
