/* 해시·MAC·KDF › PBKDF2 · scrypt · HKDF */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, kdf, HASHES } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'kdf', name: 'PBKDF2 · scrypt · HKDF', short: '비밀번호/비밀값 → 암호화 키',
    desc: 'PBKDF2는 비밀번호를 여러 번 해시해 무차별 대입을 느리게 만들고, scrypt는 여기에 많은 메모리를 요구해 GPU 공격까지 어렵게 합니다. HKDF는 키 교환으로 얻은 비밀값에서 용도별 키를 뽑아냅니다. 입력 칸에 비밀번호(또는 비밀값)를 넣으세요.',
    slow: true,
    modes: [{ id: 'run', label: '키 유도', inLabel: '비밀번호 / 비밀값', outLabel: '유도된 키' }],
    options: [
      { id: 'kdf', label: '방식', type: 'select', default: 'pbkdf2', choices: [['pbkdf2', 'PBKDF2'], ['scrypt', 'scrypt'], ['hkdf', 'HKDF']] },
      { id: 'hash', label: '해시', type: 'select', default: 'SHA-256', choices: HASHES, when: (o) => o.kdf !== 'scrypt' },
      { id: 'N', label: 'N (비용)', type: 'number', default: 16384, min: 2, when: (o) => o.kdf === 'scrypt' },
      { id: 'r', label: 'r (블록 크기)', type: 'number', default: 8, min: 1, max: 32, when: (o) => o.kdf === 'scrypt' },
      { id: 'p', label: 'p (병렬도)', type: 'number', default: 1, min: 1, max: 16, when: (o) => o.kdf === 'scrypt' },
      { id: 'salt', label: '솔트', type: 'text', default: 'salt' },
      fmtOption('saltFmt', '솔트 형식', 'text'),
      { id: 'iter', label: '반복 횟수', type: 'number', default: 100000, min: 1, when: (o) => o.kdf === 'pbkdf2' },
      { id: 'info', label: 'info', type: 'text', default: '', when: (o) => o.kdf === 'hkdf' },
      { id: 'length', label: '출력 길이(B)', type: 'number', default: 32, min: 1, max: 1024 },
      fmtOption('inFmt', '입력 형식', 'text'),
      fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
    ],
    run: async (s, o) => formatBytes(await kdf(readBytes(s, o.inFmt), o), o.outFmt),
  });
})(globalThis.DecryptLab);
