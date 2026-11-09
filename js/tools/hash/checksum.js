/* 해시·MAC·KDF › 체크섬·비암호 해시 */
(function (DL) {
  'use strict';
  const { readBytes, fmtOption, allHashes } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'checksum', name: '체크섬·비암호 해시', short: 'CRC · Adler · FNV · xxHash · Murmur',
    desc: '오류 검출과 해시 테이블에 쓰는 비암호 해시를 한 번에 계산합니다. CRC32/32C/64, CRC16(ARC·MODBUS·CCITT), Adler-32, FNV-1a, xxHash, Murmur3를 보여줍니다. 보안 용도가 아니며 쉽게 위조할 수 있습니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '계산', inLabel: '입력', outLabel: '체크섬' }],
    options: [
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      { id: 'compare', label: '비교값', type: 'text', default: '', wide: true },
    ],
    run: async (s, o) => {
      const rows = await allHashes(readBytes(s, o.inFmt), 'checksum');
      const t = (o.compare || '').trim().toLowerCase();
      const out = rows.map(([k, v]) => `${k.padEnd(13)} ${v}${t && v === t ? '   ← 일치' : ''}`).join('\n');
      if (!t) return out;
      return out + (rows.some(([, v]) => v === t) ? '' : '\n\n✗ 비교값과 일치하는 체크섬이 없습니다.');
    },
  });
})(globalThis.DecryptLab);
