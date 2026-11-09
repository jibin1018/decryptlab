/* Base 계열 인코딩 — 카테고리 셸 + 공유 헬퍼 (DL.kits.base) */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat, subtle, equalBytes, asText } = DL;

  /* ---------- 큰 수 기반 BaseX (Base58/62/36이 공유) ---------- */
  function baseXEncode(bytes, alphabet) {
    const base = BigInt(alphabet.length);
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let s = '';
    while (n > 0n) { s = alphabet[Number(n % base)] + s; n /= base; }
    for (const b of bytes) { if (b !== 0) break; s = alphabet[0] + s; }
    return s;
  }
  function baseXDecode(str, alphabet, name, caseInsensitive = false) {
    const base = BigInt(alphabet.length);
    let clean = str.replace(/\s/g, '');
    if (caseInsensitive) clean = clean.toLowerCase();
    let n = 0n;
    for (const c of clean) {
      const i = alphabet.indexOf(c);
      if (i < 0) throw new Error(`${name} 문자가 아닙니다: "${c}"`);
      n = n * base + BigInt(i);
    }
    const out = [];
    while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
    for (const c of clean) { if (c !== alphabet[0]) break; out.unshift(0); }
    return new Uint8Array(out);
  }
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const B36 = '0123456789abcdefghijklmnopqrstuvwxyz';
  const b58encode = (b) => baseXEncode(b, B58);
  const b58decode = (s) => baseXDecode(s, B58, 'Base58');
  Object.assign(DL.fn, { b58encode, b58decode });

  const IN = fmtOption('inFmt', '원본 형식', 'text', ['text', 'hex', 'base64'], 'encode');

  DL.kits.base = {
    utf8, toHex, fromHex, b64encode, b64decode, readBytes, fmtOption, concat, subtle, equalBytes, asText,
    baseXEncode, baseXDecode, B58, B62, B36, b58encode, b58decode, IN,
  };

  DL.addCategory({
    id: 'base',
    name: 'Base 계열 인코딩',
    desc: 'Base64부터 Base91·Base45·Base58Check까지 — 바이너리를 텍스트로 옮기는 인코딩 11종',
    color: 'blue',
    tools: [],
  });
})(globalThis.DecryptLab);
