/* 자동 분석 › 해시 식별기 */
(function (DL) {
  'use strict';
  const K = DL.kits.auto;

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
  K.identifyHash = identifyHash;
  K.PATTERNS = PATTERNS;
  DL.fn.identifyHash = identifyHash;

  DL.addTool('auto', {
    id: 'hashid', name: '해시 식별기', short: '길이·패턴으로 해시 종류 추정',
    desc: '해시 문자열의 길이, 문자 구성, 접두사($2b$, $6$ 등)로 어떤 알고리즘인지 추정합니다. 여러 줄을 한 번에 넣을 수 있습니다. 해시는 복호화가 아니라 같은 값인지 비교하는 용도입니다.',
    modes: [{ id: 'run', label: '식별', inLabel: '해시 (한 줄에 하나)', outLabel: '후보' }],
    run: (s) => identifyHash(s),
  });
})(globalThis.DecryptLab);
