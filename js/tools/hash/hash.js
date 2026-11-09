/* 해시·MAC·KDF › 해시 생성 */
(function (DL) {
  'use strict';
  const { readBytes, fmtOption, allHashes } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'hash', name: '해시 생성', short: 'MD5 · SHA-2/3 · BLAKE2 · RIPEMD · 체크섬',
    desc: '입력의 해시값을 한 번에 계산합니다. 해시는 단방향이라 복호화할 수 없고, 같은 입력인지 비교하는 데 씁니다. "비교값"에 해시를 넣으면 어느 알고리즘과 일치하는지 알려줍니다.',
    fileInput: true, slow: true,
    modes: [{ id: 'run', label: '해시 계산', inLabel: '입력', outLabel: '해시' }],
    options: [
      { id: 'group', label: '알고리즘', type: 'select', default: 'common', choices: [['common', 'MD5 · SHA-1 · SHA-2'], ['sha3', 'SHA-3 · Keccak'], ['blake', 'BLAKE2 · BLAKE3'], ['etc', 'RIPEMD-160 · SM3 · Whirlpool'], ['checksum', '체크섬·비암호 해시'], ['all', '전체']] },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: async (s, o) => {
      const rows = await allHashes(readBytes(s, o.inFmt), o.group);
      const t = (o.compare || '').trim().toLowerCase();
      const out = rows.map(([k, v]) => `${k.padEnd(13)} ${v}${t && v === t ? '   ← 일치' : ''}`).join('\n');
      if (!t) return out;
      return out + (rows.some(([, v]) => v === t) ? '' : '\n\n✗ 비교값과 일치하는 해시가 없습니다.');
    },
  });
})(globalThis.DecryptLab);
