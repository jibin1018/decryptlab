/* 해시·MAC·KDF › 가변 길이 해시 (XOF) */
(function (DL) {
  'use strict';
  const { readBytes, formatBytes, fmtOption, blake3, shake } = DL.kits.hash;

  DL.addTool('hash', {
    id: 'shake', name: '가변 길이 해시 (XOF)', short: 'SHAKE128 · SHAKE256 · BLAKE3',
    desc: '확장 출력 함수(XOF)로, 원하는 길이만큼 해시를 뽑을 수 있습니다. SHAKE는 SHA-3 계열로 ML-KEM·ML-DSA 같은 양자내성 암호 내부에, BLAKE3는 빠른 범용 해시·키 유도에 쓰입니다.',
    fileInput: true,
    modes: [{ id: 'run', label: '계산', inLabel: '입력', outLabel: '출력' }],
    options: [
      { id: 'bits', label: '종류', type: 'select', default: '256', choices: [['128', 'SHAKE128'], ['256', 'SHAKE256'], ['blake3', 'BLAKE3']] },
      { id: 'len', label: '출력 길이(B)', type: 'number', default: 32, min: 1, max: 4096 },
      fmtOption('inFmt', '입력 형식', 'text', ['text', 'hex', 'base64']),
      fmtOption('outFmt', '출력 형식', 'hex', ['hex', 'base64']),
    ],
    run: (s, o) => {
      const len = Number(o.len) || 32;
      if (len < 1 || len > 4096) throw new Error('출력 길이는 1–4096 B여야 합니다.');
      const bytes = readBytes(s, o.inFmt);
      return formatBytes(o.bits === 'blake3' ? blake3(bytes, len) : shake(bytes, Number(o.bits), len), o.outFmt);
    },
  });
})(globalThis.DecryptLab);
