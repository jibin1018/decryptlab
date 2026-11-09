/* 웹·문자 인코딩 › Punycode · IDN */
(function (DL) {
  'use strict';

  const P = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, bias: 72, n: 128 };
  function adapt(delta, numPoints, first) {
    let k = 0;
    delta = first ? Math.floor(delta / P.damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((P.base - P.tMin) * P.tMax) >> 1; k += P.base) delta = Math.floor(delta / (P.base - P.tMin));
    return Math.floor(k + ((P.base - P.tMin + 1) * delta) / (delta + P.skew));
  }
  const digitChar = (d) => String.fromCharCode(d + 22 + 75 * (d < 26));
  const charDigit = (c) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : P.base);
  const threshold = (k, bias) => (k <= bias ? P.tMin : k >= bias + P.tMax ? P.tMax : k - bias);
  function punyEncode(str) {
    const cps = Array.from(str, (c) => c.codePointAt(0));
    let n = P.n, delta = 0, bias = P.bias;
    let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join('');
    const b = out.length;
    let h = b;
    if (b) out += '-';
    while (h < cps.length) {
      const m = Math.min(...cps.filter((c) => c >= n));
      delta += (m - n) * (h + 1);
      n = m;
      for (const c of cps) {
        if (c < n) delta++;
        if (c === n) {
          let q = delta;
          for (let k = P.base; ; k += P.base) {
            const t = threshold(k, bias);
            if (q < t) break;
            out += digitChar(t + ((q - t) % (P.base - t)));
            q = Math.floor((q - t) / (P.base - t));
          }
          out += digitChar(q);
          bias = adapt(delta, h + 1, h === b);
          delta = 0; h++;
        }
      }
      delta++; n++;
    }
    return out;
  }
  function punyDecode(input) {
    const out = [];
    let n = P.n, i = 0, bias = P.bias;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('Punycode 기본 문자 영역에 비ASCII 문자가 있습니다.');
      out.push(input.charCodeAt(j));
    }
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = P.base; ; k += P.base) {
        if (idx >= input.length) throw new Error('Punycode 입력이 중간에 끝났습니다.');
        const digit = charDigit(input.charCodeAt(idx++));
        if (digit >= P.base) throw new Error(`Punycode 문자가 아닙니다: "${input[idx - 1]}"`);
        i += digit * w;
        const t = threshold(k, bias);
        if (digit < t) break;
        w *= P.base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const idnToAscii = (domain) => domain.split('.').map((l) => (/[^\x00-\x7f]/.test(l) ? 'xn--' + punyEncode(l.toLowerCase()) : l)).join('.');
  const idnToUnicode = (domain) => domain.split('.').map((l) => (/^xn--/i.test(l) ? punyDecode(l.slice(4).toLowerCase()) : l)).join('.');
  Object.assign(DL.fn, { punyEncode, punyDecode, idnToAscii, idnToUnicode });

  DL.addTool('web', {
    id: 'punycode', name: 'Punycode · IDN', short: '한국.kr ↔ xn--3e0b707e.kr',
    desc: '국제화 도메인(IDN)을 DNS가 이해하는 ASCII(xn--) 형태로 바꿉니다. 피싱 도메인(동형 문자 공격) 확인에 활용할 수 있습니다.',
    options: [{ id: 'domain', label: '도메인 단위 (xn-- 접두사)', type: 'checkbox', default: true }],
    encode: (s, o) => s.split(/\r?\n/).map((l) => (o.domain ? idnToAscii(l.trim()) : punyEncode(l.trim()))).join('\n'),
    decode: (s, o) => s.split(/\r?\n/).map((l) => (o.domain ? idnToUnicode(l.trim()) : punyDecode(l.trim()))).join('\n'),
  });
})(globalThis.DecryptLab);
