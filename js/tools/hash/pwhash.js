/* 해시·MAC·KDF › 비밀번호 해시 (bcrypt · Argon2) */
(function (DL) {
  'use strict';
  const { utf8, randomBytes, bcryptHashStr, bcryptGenSalt, bcryptVerify, argonEncode, argon2Compute, argon2Verify } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'pwhash', name: '비밀번호 해시', short: 'bcrypt · Argon2 (생성·검증)',
    desc: '비밀번호를 일부러 느리게(그리고 Argon2는 메모리까지 많이 써서) 해시해 무차별 대입을 어렵게 만드는 알고리즘입니다. 로그인 비밀번호 저장에 씁니다. 솔트와 파라미터를 함께 담은 문자열로 나오며, 같은 비밀번호라도 매번 달라집니다. "검증" 모드에 기존 해시 문자열을 넣으면 비밀번호가 맞는지 확인합니다. 모든 계산은 브라우저 안에서만 이뤄집니다. (Argon2는 메모리를 많이 쓰면 브라우저에서 느릴 수 있습니다.)',
    slow: true,
    modes: [
      { id: 'hash', label: '해시 생성', inLabel: '비밀번호', outLabel: '해시 문자열' },
      { id: 'verify', label: '검증', inLabel: '비밀번호', outLabel: '결과' },
    ],
    options: [
      { id: 'algo', label: '알고리즘', type: 'select', default: 'bcrypt', choices: [['bcrypt', 'bcrypt'], ['argon2id', 'Argon2id (권장)'], ['argon2i', 'Argon2i'], ['argon2d', 'Argon2d']] },
      { id: 'cost', label: 'cost (2ⁿ 반복)', type: 'number', default: 10, min: 4, max: 16, mode: 'hash', when: (o) => o.algo === 'bcrypt' },
      { id: 'mem', label: '메모리(KiB)', type: 'number', default: 8192, min: 8, max: 262144, mode: 'hash', when: (o) => o.algo !== 'bcrypt' },
      { id: 'iter', label: '반복(t)', type: 'number', default: 3, min: 1, max: 20, mode: 'hash', when: (o) => o.algo !== 'bcrypt' },
      { id: 'par', label: '병렬도(p)', type: 'number', default: 1, min: 1, max: 16, mode: 'hash', when: (o) => o.algo !== 'bcrypt' },
      { id: 'tag', label: '해시 길이(B)', type: 'number', default: 32, min: 4, max: 128, mode: 'hash', when: (o) => o.algo !== 'bcrypt' },
      { id: 'verifyHash', label: '기존 해시', type: 'textarea', default: '', wide: true, mode: 'verify', placeholder: '$2b$10$… 또는 $argon2id$v=19$m=…,t=…,p=…$…$…' },
    ],
    hash: (s, o) => {
      if (!s) throw new Error('비밀번호를 입력하세요.');
      if (o.algo === 'bcrypt') {
        const cost = Math.min(16, Math.max(4, Number(o.cost) || 10));
        return bcryptHashStr(s, bcryptGenSalt(cost));
      }
      const type = o.algo.slice(6); // id / i / d
      const p = Math.min(16, Math.max(1, Number(o.par) || 1));
      const t = Math.min(20, Math.max(1, Number(o.iter) || 3));
      const m = Math.min(262144, Math.max(8 * p, Number(o.mem) || 8192));
      const tag = Math.min(128, Math.max(4, Number(o.tag) || 32));
      const salt = randomBytes(16);
      return argonEncode(type, p, t, m, salt, argon2Compute(type, utf8(s), salt, p, t, m, tag));
    },
    verify: (s, o) => {
      const h = (o.verifyHash || '').trim();
      if (!h) throw new Error('"기존 해시" 칸에 검증할 해시 문자열을 넣으세요.');
      if (!s) throw new Error('비밀번호를 입력하세요.');
      let okMatch;
      if (/^\$2[abxy]\$/.test(h)) okMatch = bcryptVerify(s, h);
      else if (/^\$argon2(id|i|d)\$/.test(h)) okMatch = argon2Verify(s, h);
      else throw new Error('bcrypt($2…) 또는 Argon2($argon2…) 해시 문자열이어야 합니다.');
      return okMatch ? '✓ 비밀번호가 일치합니다.' : '✗ 비밀번호가 일치하지 않습니다.';
    },
  });
})(globalThis.DecryptLab);
