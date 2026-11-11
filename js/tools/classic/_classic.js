/* 고전 암호 — 카테고리 셸 + 여러 도구가 공유하는 헬퍼 (DL.kits.classic)
 * 각 도구는 같은 폴더의 개별 파일에서 DL.addTool('classic', …)로 자신을 등록한다.
 * index.html의 로드 순서(_classic.js 다음 각 도구 파일)가 곧 목차 순서다. */
(function (DL) {
  'use strict';
  const { toHex, fromHex, utf8 } = DL;

  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const mod = (n, m) => ((n % m) + m) % m;
  const lettersOnly = (s) => s.toUpperCase().replace(/[^A-Z]/g, '');

  const shiftLetter = (ch, k) => {
    const c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) return String.fromCharCode(mod(c - 65 + k, 26) + 65);
    if (c >= 97 && c <= 122) return String.fromCharCode(mod(c - 97 + k, 26) + 97);
    return ch;
  };
  const mapLetters = (s, f) => s.replace(/[A-Za-z]/g, (ch) => {
    const up = ch <= 'Z';
    const r = A[f(ch.toUpperCase().charCodeAt(0) - 65)];
    return up ? r : r.toLowerCase();
  });
  const caesar = (s, k) => s.replace(/[A-Za-z]/g, (ch) => shiftLetter(ch, k));

  function keyStream(key) {
    const k = lettersOnly(key);
    if (!k) throw new Error('키에 영문자가 하나 이상 필요합니다.');
    return Array.from(k, (c) => c.charCodeAt(0) - 65);
  }
  function vigenere(s, key, dir) {
    const k = keyStream(key);
    let j = 0;
    return mapLetters(s, (x) => mod(x + dir * k[j++ % k.length], 26));
  }
  function modInv(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
    return null;
  }

  /* ---------- Polybius 계열 공용 ---------- */
  function keySquare(key, alphabet) {
    const seen = new Set();
    let sq = '';
    for (const c of (key.toUpperCase() + alphabet)) {
      const ch = alphabet.length === 25 && c === 'J' ? 'I' : c;
      if (alphabet.includes(ch) && !seen.has(ch)) { seen.add(ch); sq += ch; }
    }
    return sq;
  }
  const A25 = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  const A36 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const prep25 = (s) => lettersOnly(s).replace(/J/g, 'I');

  /* ---------- 열 전치 공용 (columnar, ADFGVX가 공유) ---------- */
  function keyOrder(key) {
    const k = key.toUpperCase();
    if (!k) throw new Error('전치 키를 입력하세요.');
    return Array.from(k).map((c, i) => [c, i]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1])).map((x) => x[1]);
  }
  function columnarEnc(s, key) {
    const order = keyOrder(key);
    const n = order.length;
    const chars = Array.from(s);
    return order.map((col) => chars.filter((_, i) => i % n === col).join('')).join('');
  }
  function columnarDec(s, key) {
    const order = keyOrder(key);
    const n = order.length;
    const chars = Array.from(s);
    const rows = Math.ceil(chars.length / n);
    const full = chars.length % n || n;
    const cols = Array(n);
    let pos = 0;
    for (const col of order) {
      const len = col < full ? rows : rows - 1;
      cols[col] = chars.slice(pos, pos + len); pos += len;
    }
    let out = '';
    for (let r = 0; r < rows; r++) for (let c = 0; c < n; c++) if (cols[c][r] !== undefined) out += cols[c][r];
    return out;
  }

  /* ---------- 빈도 분석 공용 ---------- */
  const EN_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074];
  const counts = (t) => { const c = Array(26).fill(0); for (const ch of t) c[ch.charCodeAt(0) - 65]++; return c; };
  const ioc = (t) => { const c = counts(t); const n = t.length; return n < 2 ? 0 : c.reduce((a, f) => a + f * (f - 1), 0) / (n * (n - 1)); };
  const chi2 = (c, n) => c.reduce((a, f, i) => { const e = (EN_FREQ[i] / 100) * n; return a + ((f - e) ** 2) / e; }, 0);
  function bestShift(t) {
    let best = { shift: 0, score: Infinity };
    for (let s = 0; s < 26; s++) {
      const shifted = Array.from(t, (c) => A[mod(c.charCodeAt(0) - 65 - s, 26)]).join('');
      const sc = chi2(counts(shifted), t.length);
      if (sc < best.score) best = { shift: s, score: sc };
    }
    return best;
  }

  const ENC_DEC = [{ id: 'encode', label: '암호화' }, { id: 'decode', label: '복호화' }];
  const SYM = [{ id: 'encode', label: '변환' }];

  // 여러 도구가 공유하는 헬퍼 모음
  DL.kits.classic = {
    utf8, toHex, fromHex,
    A, mod, lettersOnly, shiftLetter, mapLetters, caesar, keyStream, vigenere, modInv,
    keySquare, A25, A36, prep25, keyOrder, columnarEnc, columnarDec,
    EN_FREQ, counts, ioc, chi2, bestShift, ENC_DEC, SYM,
  };
  // 다른 카테고리(자동 분석 등)가 쓰는 공용 함수
  Object.assign(DL.fn, { caesar, vigenere, ioc: (s) => ioc(lettersOnly(s)), bestShift: (s) => bestShift(lettersOnly(s)) });

  DL.addCategory({
    id: 'classic',
    name: '고전 암호',
    desc: '카이사르·비즈네르 등 치환·전치 고전 암호',
    color: 'purple',
    tools: [],
  });
})(globalThis.DecryptLab);
