/* 해시·MAC·KDF › 해시 크래커 (본인 소유·실습용 해시 전용)
 * 사전 공격 + 변형 + 선택적 짧은 무차별 대입으로 해시의 원본 문자열을 찾는다.
 * 모든 계산은 브라우저 안에서만 이뤄지며, 강한 무작위 비밀번호는 복구되지 않는다. */
(function (DL) {
  'use strict';
  const { utf8, toHex, md5, sha, sha3, keccakHash, ripemd160, sm3, whirlpool, blake2b } = DL.kits.hash;

  // 알고리즘별 해시 함수 (hex 반환). afn은 비동기(Web Crypto).
  const HASHERS = {
    md5: { len: 32, name: 'MD5', fn: (b) => toHex(md5(b)) },
    sha1: { len: 40, name: 'SHA-1', afn: async (b) => toHex(await sha('SHA-1', b)) },
    sha256: { len: 64, name: 'SHA-256', afn: async (b) => toHex(await sha('SHA-256', b)) },
    sha384: { len: 96, name: 'SHA-384', afn: async (b) => toHex(await sha('SHA-384', b)) },
    sha512: { len: 128, name: 'SHA-512', afn: async (b) => toHex(await sha('SHA-512', b)) },
    sha3_256: { len: 64, name: 'SHA3-256', fn: (b) => toHex(sha3(b, 256)) },
    sha3_512: { len: 128, name: 'SHA3-512', fn: (b) => toHex(sha3(b, 512)) },
    keccak256: { len: 64, name: 'Keccak-256', fn: (b) => toHex(keccakHash(b, 256)) },
    ripemd160: { len: 40, name: 'RIPEMD-160', fn: (b) => toHex(ripemd160(b)) },
    sm3: { len: 64, name: 'SM3', fn: (b) => toHex(sm3(b)) },
    blake2b256: { len: 64, name: 'BLAKE2b-256', fn: (b) => toHex(blake2b(b, 32)) },
    whirlpool: { len: 128, name: 'Whirlpool', fn: (b) => toHex(whirlpool(b)) },
  };
  const ALGO_CHOICES = [['auto', '자동 (길이로 추정)'], ['md5', 'MD5'], ['sha1', 'SHA-1'], ['sha256', 'SHA-256'], ['sha384', 'SHA-384'], ['sha512', 'SHA-512'], ['sha3_256', 'SHA3-256'], ['sha3_512', 'SHA3-512'], ['keccak256', 'Keccak-256'], ['ripemd160', 'RIPEMD-160'], ['sm3', 'SM3'], ['blake2b256', 'BLAKE2b-256'], ['whirlpool', 'Whirlpool']];

  // 자주 쓰이는 약한 비밀번호(사전 공격 기본 목록)
  const COMMON = ('password 123456 123456789 12345678 12345 1234567 qwerty abc123 password1 111111 1234567890 iloveyou admin welcome monkey login 000000 letmein dragon 123123 baseball football superman batman trustno1 passw0rd master hello freedom whatever qazwsx 654321 michael shadow jennifer 7777777 jordan harley hunter buster soccer tigger charlie andrew michelle love sunshine princess flower hottie loveme zaq12wsx password123 qwerty123 1q2w3e4r admin123 root toor test guest user changeme secret ninja azerty 123qwe pokemon starwars computer internet samsung google facebook apple linux ubuntu mustang pepper banana orange purple yellow summer winter spring autumn liverpool arsenal chelsea 1qaz2wsx qwertyuiop asdfghjkl zxcvbnm q1w2e3r4 flagflag ctf admin1 Password Password1 Welcome1 Admin123 P@ssw0rd').split(/\s+/);

  function* mangle(w) {
    const lw = w.toLowerCase();
    const caps = new Set([w, lw, w.toUpperCase(), lw.charAt(0).toUpperCase() + lw.slice(1)]);
    const suffixes = ['', '1', '2', '3', '12', '123', '1234', '!', '!!', '123!', '2022', '2023', '2024', '2025', '01', '007', '00', '69', '321', '0', '?', '#', '@'];
    for (const c of caps) for (const s of suffixes) yield c + s;
    yield lw.replace(/a/g, '@').replace(/e/g, '3').replace(/o/g, '0').replace(/i/g, '1').replace(/s/g, '$'); // 리트
  }
  function* bruteGen(o) {
    const sets = { lower: 'abcdefghijklmnopqrstuvwxyz', digits: '0123456789', alnum: 'abcdefghijklmnopqrstuvwxyz0123456789', loweralpha: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' };
    const chars = Array.from(sets[o.charset] || sets.lower);
    const maxLen = Math.min(6, Math.max(1, Number(o.maxLen) || 4));
    for (let len = 1; len <= maxLen; len++) {
      const idx = new Array(len).fill(0);
      for (;;) {
        yield idx.map((i) => chars[i]).join('');
        let p = len - 1;
        while (p >= 0) { if (++idx[p] < chars.length) break; idx[p] = 0; p--; }
        if (p < 0) break;
      }
    }
  }
  function* candidates(o) {
    const seen = new Set();
    const bases = [];
    if (o.useCommon) bases.push(...COMMON);
    if (o.wordlist) bases.push(...o.wordlist.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
    for (const base of bases) {
      const forms = o.mangle ? mangle(base) : [base];
      for (const f of forms) { if (f.length <= 64 && !seen.has(f)) { seen.add(f); yield f; } }
    }
    if (o.brute) yield* bruteGen(o);
  }

  const CAP = 3000000; // 과도한 연산 방지
  async function hashCrack(input, o) {
    const targets = input.split(/\r?\n/).map((l) => l.trim().replace(/^0x/i, '').toLowerCase()).filter((l) => /^[0-9a-f]+$/.test(l));
    if (!targets.length) throw new Error('16진수 해시를 한 줄에 하나씩 넣으세요.');
    const salt = o.salt || '';
    const wrap = (w) => (o.saltPos === 'prefix' ? salt + w : o.saltPos === 'suffix' ? w + salt : w);
    const hashHex = (h, b) => (h.afn ? h.afn(b) : h.fn(b));
    const results = [];
    for (const target of targets) {
      const applicable = o.algo === 'auto' ? Object.values(HASHERS).filter((h) => h.len === target.length) : [HASHERS[o.algo]];
      if (!applicable.length) { results.push(`✗ ${target.slice(0, 24)}…  — 길이 ${target.length}에 맞는 알고리즘이 없습니다.`); continue; }
      let found = null, tried = 0;
      for (const cand of candidates(o)) {
        if (++tried > CAP) break;
        const bytes = utf8(wrap(cand));
        for (const h of applicable) {
          if ((await hashHex(h, bytes)) === target) { found = { cand, algo: h.name }; break; }
        }
        if (found) break;
      }
      const head = target.length > 24 ? target.slice(0, 24) + '…' : target;
      results.push(found
        ? `✓ ${head}\n    → "${found.cand}"  (${found.algo}${salt ? `, 솔트 ${o.saltPos === 'prefix' ? '앞' : '뒤'}` : ''})  ·  ${tried.toLocaleString()}개째`
        : `✗ ${head}\n    ${tried.toLocaleString()}개 시도했지만 찾지 못했습니다.${tried >= CAP ? ' (한도 도달)' : ''}`);
    }
    return results.join('\n\n') + '\n\n※ 본인 소유·실습(CTF)용 해시에만 사용하세요. 남의 비밀번호를 알아내는 용도로 쓰지 마세요. 모든 계산은 브라우저 안에서만 이뤄지며, 강한 무작위 비밀번호는 복구되지 않습니다.';
  }

  DL.addTool('hash', {
    id: 'hashcrack', name: '해시 크래커', short: 'MD5·SHA 등 사전/무차별 대입',
    desc: '해시의 원본 문자열을 사전 공격(내장 약한 비밀번호 + 변형)과 선택적 짧은 무차별 대입으로 찾습니다. 본인 소유·실습(CTF)용 해시의 원문 복구에만 쓰세요. 해시는 복호화가 아니라 후보를 해시해 비교하는 방식이며, 강한 무작위 값은 복구되지 않습니다. 남의 비밀번호를 알아내는 용도로 쓰지 마세요. 모든 계산은 브라우저 안에서만 이뤄집니다.',
    slow: true,
    modes: [{ id: 'run', label: '크래킹', inLabel: '해시 (한 줄에 하나)', outLabel: '결과', placeholder: '5f4dcc3b5aa765d61d8327deb882cf99 (MD5 of "password")' }],
    options: [
      { id: 'algo', label: '알고리즘', type: 'select', default: 'auto', choices: ALGO_CHOICES },
      { id: 'useCommon', label: '내장 약한 비밀번호 목록 사용', type: 'checkbox', default: true },
      { id: 'mangle', label: '변형 추가 (대소문자·숫자·기호·리트)', type: 'checkbox', default: true },
      { id: 'wordlist', label: '단어 목록 (한 줄에 하나)', type: 'textarea', default: '', wide: true, placeholder: '후보 단어를 한 줄에 하나씩 붙여 넣으세요 (선택)' },
      { id: 'salt', label: '솔트 (선택)', type: 'text', default: '' },
      { id: 'saltPos', label: '솔트 위치', type: 'select', default: 'prefix', when: (o) => !!o.salt, choices: [['prefix', '해시(솔트+비밀번호)'], ['suffix', '해시(비밀번호+솔트)']] },
      { id: 'brute', label: '짧은 무차별 대입도 시도', type: 'checkbox', default: false },
      { id: 'charset', label: '문자셋', type: 'select', default: 'lower', when: (o) => o.brute, choices: [['lower', '소문자 (a–z)'], ['digits', '숫자 (0–9)'], ['alnum', '소문자+숫자'], ['loweralpha', '대소문자']] },
      { id: 'maxLen', label: '최대 길이', type: 'number', default: 4, min: 1, max: 6, when: (o) => o.brute },
    ],
    run: (s, o) => (s.trim() ? hashCrack(s, o) : ''),
  });
})(globalThis.DecryptLab);
