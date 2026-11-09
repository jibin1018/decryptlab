/* Base 계열 › Base58Check */
(function (DL) {
  'use strict';
  const { toHex, readBytes, concat, subtle, equalBytes, b58encode, b58decode, IN } = DL.kits.base;

  async function sha256d(bytes) {
    const h1 = new Uint8Array(await subtle().digest('SHA-256', bytes));
    return new Uint8Array(await subtle().digest('SHA-256', h1));
  }
  async function b58checkEncode(payload) {
    return b58encode(concat(payload, (await sha256d(payload)).slice(0, 4)));
  }
  async function b58checkDecode(s) {
    const all = b58decode(s);
    if (all.length < 5) throw new Error('Base58Check 데이터가 너무 짧습니다.');
    const payload = all.slice(0, -4);
    const ok = equalBytes((await sha256d(payload)).slice(0, 4), all.slice(-4));
    return { payload, ok, checksum: all.slice(-4) };
  }
  Object.assign(DL.fn, { b58checkEncode, b58checkDecode });

  DL.addTool('base', {
    id: 'base58check', name: 'Base58Check', short: 'Base58 + 4바이트 체크섬',
    desc: '데이터 뒤에 SHA-256을 두 번 적용한 해시의 앞 4바이트를 붙여 Base58로 인코딩합니다. 비트코인 주소와 WIF 키 형식입니다. 디코딩 시 체크섬을 검증합니다.',
    options: [{ ...IN, default: 'hex' }],
    encode: (s, o) => b58checkEncode(readBytes(s, o.inFmt)),
    decode: async (s) => {
      const { payload, ok, checksum } = await b58checkDecode(s.trim());
      return [
        `체크섬    ${ok ? '✓ 일치' : '✗ 불일치 — 데이터가 손상되었거나 Base58Check가 아닙니다'} (${toHex(checksum)})`,
        `버전 바이트 0x${toHex(payload.slice(0, 1))}${payload[0] === 0 ? ' (비트코인 P2PKH 주소)' : payload[0] === 5 ? ' (비트코인 P2SH 주소)' : payload[0] === 0x80 ? ' (WIF 개인키)' : ''}`,
        `페이로드  ${toHex(payload)}`,
        `길이      ${payload.length} B`,
      ].join('\n');
    },
  });
})(globalThis.DecryptLab);
