/* 진법·데이터 표현 — 카테고리 셸 + 공유 헬퍼 (DL.kits.radix) */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex } = DL;

  const SEP = { space: ' ', none: '', comma: ', ', newline: '\n' };
  const SEP_OPTION = {
    id: 'sep', label: '구분자', type: 'select', default: 'space', mode: 'encode',
    choices: [['space', '공백'], ['none', '없음'], ['comma', '쉼표'], ['newline', '줄바꿈']],
  };

  function radixEncode(bytes, radix, width, sep) {
    return Array.from(bytes, (b) => b.toString(radix).padStart(width, '0')).join(SEP[sep] ?? ' ');
  }
  function radixDecode(s, radix) {
    const re = radix === 2 ? /[^01]/ : radix === 8 ? /[^0-7]/ : /[^0-9]/;
    let tokens = s.trim().split(/[\s,;]+/).filter(Boolean);
    if (tokens.length === 1 && radix === 2 && tokens[0].length > 8) {
      if (tokens[0].length % 8) throw new Error('구분자 없는 2진수는 8의 배수 길이여야 합니다.');
      tokens = tokens[0].match(/.{8}/g);
    }
    if (tokens.length === 1 && radix === 8 && tokens[0].length > 3 && tokens[0].length % 3 === 0) tokens = tokens[0].match(/.{3}/g);
    return new Uint8Array(tokens.map((t) => {
      if (re.test(t)) throw new Error(`올바르지 않은 값: "${t}"`);
      const v = parseInt(t, radix);
      if (v > 255) throw new Error(`바이트 범위(0–255)를 벗어난 값: "${t}"`);
      return v;
    }));
  }

  /* ---------- 임의 진법 정수 변환 ---------- */
  const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  function parseBig(str, radix) {
    let s = str.trim().replace(/[_\s]/g, '');
    let neg = false;
    if (s.startsWith('-')) { neg = true; s = s.slice(1); }
    if (radix === 16) s = s.replace(/^0x/i, '');
    if (radix === 2) s = s.replace(/^0b/i, '');
    if (radix === 8) s = s.replace(/^0o/i, '');
    if (!s) throw new Error('숫자를 입력하세요.');
    const alpha = DIGITS.slice(0, radix);
    let n = 0n;
    for (const c of s) {
      const d = (radix <= 36 ? alpha.indexOf(c.toLowerCase()) : alpha.indexOf(c));
      if (d < 0) throw new Error(`${radix}진수에 쓸 수 없는 문자: "${c}"`);
      n = n * BigInt(radix) + BigInt(d);
    }
    return neg ? -n : n;
  }
  function bigToRadix(n, radix) {
    if (n === 0n) return '0';
    const neg = n < 0n;
    let v = neg ? -n : n, s = '';
    const r = BigInt(radix);
    while (v > 0n) { s = DIGITS[Number(v % r)] + s; v /= r; }
    return (neg ? '-' : '') + s;
  }

  DL.kits.radix = { utf8, toHex, fromHex, SEP, SEP_OPTION, radixEncode, radixDecode, parseBig, bigToRadix };
  Object.assign(DL.fn, { radixEncode, radixDecode, parseBig, bigToRadix });

  DL.addCategory({
    id: 'radix',
    name: '진법·데이터 표현',
    desc: '진법·부동소수점·엔디안·정수 표현',
    color: 'green',
    tools: [],
  });
})(globalThis.DecryptLab);
