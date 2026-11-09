/* 대칭키 암호 › OpenSSL · CryptoJS 호환 */
(function (DL) {
  'use strict';
  const { utf8, readBytes, formatBytes, concat, equalBytes, b64decode, b64encode, randomBytes, blockCrypt, opensslDerive, AES, SALTED, ENC_DEC, ptFmt } = DL.kits.symmetric;

  DL.addTool('symmetric', {
    id: 'openssl', name: 'OpenSSL · CryptoJS 호환', short: '비밀번호 기반 "U2FsdGVkX1…"',
    desc: '"openssl enc -aes-256-cbc"나 CryptoJS.AES.encrypt(텍스트, "비밀번호")가 만드는 형식입니다. "Salted__" + 8 B 솔트 + 암호문 구조이며, Base64로 "U2FsdGVkX1"로 시작합니다. 비밀번호에서 키와 IV를 유도합니다.',
    slow: true, modes: ENC_DEC,
    options: [
      { id: 'password', label: '비밀번호', type: 'text', default: 'password' },
      { id: 'bits', label: 'AES', type: 'select', default: '32', choices: [['32', 'AES-256-CBC'], ['24', 'AES-192-CBC'], ['16', 'AES-128-CBC']] },
      { id: 'kdf', label: '키 유도', type: 'select', default: 'md5', choices: [['md5', 'EVP_BytesToKey (MD5, CryptoJS 기본)'], ['pbkdf2', 'PBKDF2-SHA256 (openssl -pbkdf2)']] },
      { id: 'iter', label: '반복 횟수', type: 'number', default: 10000, min: 1, when: (o) => o.kdf === 'pbkdf2' },
      ptFmt,
    ],
    encrypt: async (s, o) => {
      const salt = randomBytes(8);
      const { key, iv } = await opensslDerive(utf8(o.password), salt, Number(o.bits), o);
      const ct = blockCrypt(AES, key, iv, readBytes(s, o.ptFmt), { mode: 'cbc', padding: 'pkcs7' }, false);
      return b64encode(concat(SALTED, salt, ct));
    },
    decrypt: async (s, o) => {
      const data = b64decode(s.trim());
      if (!equalBytes(data.slice(0, 8), SALTED)) throw new Error('"Salted__" 헤더가 없습니다. Base64가 "U2FsdGVkX1"로 시작하는지 확인하세요.');
      const { key, iv } = await opensslDerive(utf8(o.password), data.slice(8, 16), Number(o.bits), o);
      return formatBytes(blockCrypt(AES, key, iv, data.slice(16), { mode: 'cbc', padding: 'pkcs7' }, true), o.ptFmt);
    },
  });
})(globalThis.DecryptLab);
