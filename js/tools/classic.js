/* 고전 암호 */
(function (DL) {
  'use strict';
  const { utf8, toHex, fromHex } = DL;

  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const mod = (n, m) => ((n % m) + m) % m;
  const lettersOnly = (s) => s.toUpperCase().replace(/[^A-Z]/g, '');

  /* ---------- 단순 치환 ---------- */
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
  const rot47 = (s) => s.replace(/[!-~]/g, (ch) => String.fromCharCode(33 + ((ch.charCodeAt(0) - 33 + 47) % 94)));
  const atbash = (s) => mapLetters(s, (x) => 25 - x);

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
  function beaufort(s, key) {
    const k = keyStream(key);
    let j = 0;
    return mapLetters(s, (x) => mod(k[j++ % k.length] - x, 26));
  }
  function autokey(s, key, dir) {
    const stream = keyStream(key);
    let j = 0;
    return mapLetters(s, (x) => {
      const out = mod(x + dir * stream[j++], 26);
      stream.push(dir > 0 ? x : out); // 키 스트림은 평문으로 이어진다
      return out;
    });
  }

  function modInv(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
    return null;
  }
  function affine(s, a, b, dir) {
    a = Number(a); b = Number(b);
    const inv = modInv(a, 26);
    if (inv === null) throw new Error(`a=${a}은(는) 26과 서로소가 아니라 복호화할 수 없습니다. (가능: 1,3,5,7,9,11,15,17,19,21,23,25)`);
    return mapLetters(s, (x) => (dir > 0 ? mod(a * x + b, 26) : mod(inv * (x - b), 26)));
  }

  function substitution(s, key, dir) {
    const k = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (k.length !== 26 || new Set(k).size !== 26) throw new Error('키는 A–Z가 한 번씩 모두 들어간 26글자여야 합니다.');
    return mapLetters(s, (x) => (dir > 0 ? k.charCodeAt(x) - 65 : k.indexOf(A[x])));
  }

  /* ---------- Polybius 계열 ---------- */
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

  function polybiusEnc(s, key) {
    const sq = keySquare(key, A25);
    return Array.from(prep25(s), (c) => { const i = sq.indexOf(c); return `${Math.floor(i / 5) + 1}${(i % 5) + 1}`; }).join(' ');
  }
  function polybiusDec(s, key) {
    const sq = keySquare(key, A25);
    const d = s.replace(/[^1-5]/g, '');
    if (!d) throw new Error('1–5 사이의 좌표 숫자가 없습니다.');
    if (d.length % 2) throw new Error('좌표 숫자의 개수가 홀수입니다.');
    return d.match(/../g).map((p) => sq[(p[0] - 1) * 5 + (p[1] - 1)]).join('');
  }

  function playfairPairs(s) {
    const t = prep25(s);
    const pairs = [];
    for (let i = 0; i < t.length;) {
      const a = t[i];
      let b = t[i + 1];
      if (!b) { b = a === 'X' ? 'Q' : 'X'; i++; }
      else if (a === b) { b = a === 'X' ? 'Q' : 'X'; i++; }
      else i += 2;
      pairs.push(a + b);
    }
    return pairs;
  }
  function playfair(s, key, dir) {
    const sq = keySquare(key, A25);
    const pos = (c) => { const i = sq.indexOf(c); return [Math.floor(i / 5), i % 5]; };
    const pairs = dir > 0 ? playfairPairs(s) : (() => {
      const t = prep25(s);
      if (!t) throw new Error('영문자가 없습니다.');
      if (t.length % 2) throw new Error('Playfair 암호문은 글자 수가 짝수여야 합니다.');
      return t.match(/../g);
    })();
    return pairs.map(([a, b]) => {
      const [r1, c1] = pos(a), [r2, c2] = pos(b);
      if (r1 === r2) return sq[r1 * 5 + mod(c1 + dir, 5)] + sq[r2 * 5 + mod(c2 + dir, 5)];
      if (c1 === c2) return sq[mod(r1 + dir, 5) * 5 + c1] + sq[mod(r2 + dir, 5) * 5 + c2];
      return sq[r1 * 5 + c2] + sq[r2 * 5 + c1];
    }).join(' ');
  }

  function bifid(s, key, dir, period) {
    const sq = keySquare(key, A25);
    const t = prep25(s);
    const p = Number(period) > 0 ? Number(period) : t.length;
    let out = '';
    for (let start = 0; start < t.length; start += p) {
      const block = t.slice(start, start + p);
      const coords = Array.from(block, (c) => { const i = sq.indexOf(c); return [Math.floor(i / 5), i % 5]; });
      if (dir > 0) {
        const line = [...coords.map((c) => c[0]), ...coords.map((c) => c[1])];
        for (let i = 0; i < line.length; i += 2) out += sq[line[i] * 5 + line[i + 1]];
      } else {
        const line = coords.flat();
        const n = block.length;
        for (let i = 0; i < n; i++) out += sq[line[i] * 5 + line[n + i]];
      }
    }
    return out;
  }

  /* ---------- 전치 ---------- */
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
  function railEncode(s, rails) {
    const chars = Array.from(s);
    if (rails < 2) return s;
    const rows = Array.from({ length: rails }, () => []);
    let r = 0, d = 1;
    for (const c of chars) {
      rows[r].push(c);
      if (r === 0) d = 1; else if (r === rails - 1) d = -1;
      r += d;
    }
    return rows.flat().join('');
  }
  function railDecode(s, rails) {
    const chars = Array.from(s);
    if (rails < 2) return s;
    const pattern = [];
    let r = 0, d = 1;
    for (let i = 0; i < chars.length; i++) {
      pattern.push(r);
      if (r === 0) d = 1; else if (r === rails - 1) d = -1;
      r += d;
    }
    const counts = Array(rails).fill(0);
    pattern.forEach((p) => counts[p]++);
    const rows = []; let pos = 0;
    for (let i = 0; i < rails; i++) { rows.push(chars.slice(pos, pos + counts[i])); pos += counts[i]; }
    const idx = Array(rails).fill(0);
    return pattern.map((p) => rows[p][idx[p]++]).join('');
  }

  /* ---------- ADFGVX ---------- */
  function adfgvx(s, squareKey, transKey, dir, variant) {
    const labels = variant === 'adfgx' ? 'ADFGX' : 'ADFGVX';
    const size = labels.length;
    const sq = keySquare(squareKey, size === 5 ? A25 : A36);
    if (dir > 0) {
      const t = size === 5 ? prep25(s) : s.toUpperCase().replace(/[^A-Z0-9]/g, '');
      const mid = Array.from(t, (c) => { const i = sq.indexOf(c); return labels[Math.floor(i / size)] + labels[i % size]; }).join('');
      return columnarEnc(mid, transKey);
    }
    const t = s.toUpperCase().replace(new RegExp(`[^${labels}]`, 'g'), '');
    if (!t) throw new Error(`${labels} 문자가 없습니다.`);
    const mid = columnarDec(t, transKey);
    if (mid.length % 2) throw new Error('전치를 푼 결과의 길이가 홀수입니다. 키를 확인하세요.');
    return mid.match(/../g).map((p) => sq[labels.indexOf(p[0]) * size + labels.indexOf(p[1])]).join('');
  }

  /* ---------- Hill ---------- */
  function hillMatrix(key) {
    const t = key.trim();
    let nums;
    if (/^[\d\s,;-]+$/.test(t)) nums = t.split(/[\s,;]+/).filter(Boolean).map(Number);
    else nums = Array.from(lettersOnly(t), (c) => c.charCodeAt(0) - 65);
    const n = Math.round(Math.sqrt(nums.length));
    if (n < 2 || n * n !== nums.length) throw new Error('키는 4개(2×2) 또는 9개(3×3) 숫자, 혹은 4/9글자 영단어여야 합니다.');
    return { n, m: Array.from({ length: n }, (_, r) => nums.slice(r * n, r * n + n).map((v) => mod(v, 26))) };
  }
  function det(m) {
    if (m.length === 2) return m[0][0] * m[1][1] - m[0][1] * m[1][0];
    return m[0].reduce((acc, v, c) => acc + (c % 2 ? -1 : 1) * v * det(m.slice(1).map((row) => row.filter((_, j) => j !== c))), 0);
  }
  function invMatrix(m) {
    const n = m.length;
    const d = mod(det(m), 26);
    const dInv = modInv(d, 26);
    if (dInv === null) throw new Error(`키 행렬의 행렬식(${d})이 26과 서로소가 아니라 역행렬이 없습니다. 다른 키를 사용하세요.`);
    if (n === 2) return [[m[1][1], -m[0][1]], [-m[1][0], m[0][0]]].map((r) => r.map((v) => mod(v * dInv, 26)));
    const adj = Array.from({ length: n }, () => Array(n).fill(0));
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
      const minor = m.filter((_, i) => i !== r).map((row) => row.filter((_, j) => j !== c));
      adj[c][r] = ((r + c) % 2 ? -1 : 1) * det(minor);
    }
    return adj.map((row) => row.map((v) => mod(v * dInv, 26)));
  }
  function hill(s, key, dir) {
    const { n, m } = hillMatrix(key);
    const mat = dir > 0 ? m : invMatrix(m);
    if (dir > 0) invMatrix(m); // 복호화 불가능한 키는 미리 경고
    const t = lettersOnly(s);
    const padded = t + 'X'.repeat((n - (t.length % n)) % n);
    let out = '';
    for (let i = 0; i < padded.length; i += n) {
      const v = Array.from(padded.slice(i, i + n), (c) => c.charCodeAt(0) - 65);
      for (let r = 0; r < n; r++) out += A[mod(mat[r].reduce((acc, x, c) => acc + x * v[c], 0), 26)];
    }
    return out;
  }

  /* ---------- Bacon ---------- */
  function baconTable(variant) {
    const letters = variant === '26' ? A : 'ABCDEFGHIKLMNOPQRSTUWXYZ';
    return letters.split('').map((c, i) => [c, i.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B')]);
  }
  function baconEnc(s, variant) {
    const table = Object.fromEntries(baconTable(variant));
    const t = variant === '26' ? lettersOnly(s) : lettersOnly(s).replace(/J/g, 'I').replace(/V/g, 'U');
    return Array.from(t, (c) => table[c]).join(' ');
  }
  function baconDec(s, variant) {
    let t = s.trim();
    if (/^[01\s]+$/.test(t)) t = t.replace(/0/g, 'A').replace(/1/g, 'B');
    else if (!/^[ABab\s]+$/.test(t)) {
      // 대소문자 스테가노그래피: 소문자=A, 대문자=B
      t = Array.from(s.replace(/[^A-Za-z]/g, ''), (c) => (c === c.toLowerCase() ? 'A' : 'B')).join('');
    }
    t = t.toUpperCase().replace(/[^AB]/g, '');
    if (!t) throw new Error('A/B 기호(또는 0/1, 대소문자 패턴)가 없습니다.');
    if (t.length % 5) throw new Error(`A/B 기호가 5의 배수가 아닙니다 (현재 ${t.length}개).`);
    const rev = Object.fromEntries(baconTable(variant).map(([c, code]) => [code, c]));
    return t.match(/.{5}/g).map((g) => rev[g] || '?').join('');
  }

  /* ---------- 모스 ---------- */
  const MORSE = {
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
    K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
    U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
    0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.',
  };
  const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
  function morseEncode(s) {
    return s.toUpperCase().trim().split(/\s+/).map((w) => Array.from(w).map((c) => {
      if (!MORSE[c]) throw new Error(`모스 부호로 표현할 수 없는 문자: "${c}"`);
      return MORSE[c];
    }).join(' ')).join(' / ');
  }
  function morseDecode(s) {
    const norm = s.replace(/[·•]/g, '.').replace(/[_−–—]/g, '-').trim();
    return norm.split(/\s*[\/|]\s*|\s{3,}/).map((w) => w.trim().split(/\s+/).filter(Boolean).map((code) => {
      if (!MORSE_REV[code]) throw new Error(`알 수 없는 모스 부호: "${code}"`);
      return MORSE_REV[code];
    }).join('')).join(' ');
  }

  /* ---------- XOR ---------- */
  function xorBytes(data, key) {
    if (!key.length) throw new Error('XOR 키를 입력하세요.');
    return data.map((b, i) => b ^ key[i % key.length]);
  }
  const xorKey = (o) => (o.keyType === 'hex' ? fromHex(o.key || '') : utf8(o.key || ''));

  /* ---------- 빈도 분석 / 비즈네르 해독 ---------- */
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
  function analyzeClassic(s) {
    const t = lettersOnly(s);
    if (t.length < 20) throw new Error('신뢰할 수 있는 분석에는 영문자가 최소 20자 이상 필요합니다.');
    const c = counts(t);
    const ic = ioc(t);
    const lines = [];
    lines.push(`영문자 ${t.length}자 · 일치 지수(IC) ${ic.toFixed(4)}`);
    lines.push(`  영어 평문/단일 치환 ≈ 0.066, 무작위/다중 치환 ≈ 0.038`);
    lines.push(ic > 0.058 ? '  → 단일 치환(카이사르·Atbash·Affine·치환 암호) 또는 전치 암호일 가능성이 높습니다.'
      : ic < 0.047 ? '  → 비즈네르 같은 다중 치환 암호일 가능성이 높습니다.' : '  → 판단이 애매합니다. 텍스트가 더 길면 정확해집니다.');
    lines.push('', '■ 문자 빈도 (상위 10)');
    const top = c.map((f, i) => [A[i], f]).sort((a, b) => b[1] - a[1]).slice(0, 10);
    for (const [ch, f] of top) {
      const p = (f / t.length) * 100;
      lines.push(`  ${ch}  ${'█'.repeat(Math.round(p / 1.5)).padEnd(10)} ${p.toFixed(1)}%`);
    }
    const cs = bestShift(t);
    lines.push('', `■ 카이사르로 가정했을 때 최적 시프트: ${cs.shift} (χ² ${cs.score.toFixed(1)})`);
    lines.push(`  ${caesar(s, -cs.shift).slice(0, 200)}`);

    // 비즈네르 키 길이 추정 (열별 평균 IC)
    const cands = [];
    for (let L = 1; L <= Math.min(20, Math.floor(t.length / 4)); L++) {
      let sum = 0;
      for (let k = 0; k < L; k++) sum += ioc(t.split('').filter((_, i) => i % L === k).join(''));
      cands.push({ L, ic: sum / L });
    }
    // 긴 키는 짧은 키의 배수에서도 높은 IC가 나오므로, 0.06에 가까운 가장 짧은 길이를 우선한다
    const good = cands.filter((x) => x.ic > 0.055);
    const ranked = good.length ? good.sort((a, b) => a.L - b.L) : cands.slice().sort((a, b) => b.ic - a.ic);
    lines.push('', '■ 비즈네르로 가정한 키 길이 후보 (열별 평균 IC)');
    lines.push('  ' + cands.slice().sort((a, b) => b.ic - a.ic).slice(0, 5).map((x) => `${x.L}글자: ${x.ic.toFixed(4)}`).join('  ·  '));
    for (const { L } of ranked.slice(0, 2)) {
      if (L === 1) continue;
      let key = '';
      for (let k = 0; k < L; k++) key += A[bestShift(t.split('').filter((_, i) => i % L === k).join('')).shift];
      lines.push('', `  키 길이 ${L} → 추정 키 "${key}"`);
      lines.push(`  ${vigenere(s, key, -1).slice(0, 300)}`);
    }
    lines.push('', '※ 통계적 추정이므로 짧은 텍스트나 영어가 아닌 평문에서는 틀릴 수 있습니다.');
    return lines.join('\n');
  }

  Object.assign(DL.fn, { caesar, rot47, atbash, vigenere, xorBytes, morseDecode, ioc: (s) => ioc(lettersOnly(s)), bestShift: (s) => bestShift(lettersOnly(s)) });

  const ENC_DEC = [{ id: 'encode', label: '암호화' }, { id: 'decode', label: '복호화' }];
  const SYM = [{ id: 'encode', label: '변환' }];

  DL.addCategory({
    id: 'classic',
    name: '고전 암호',
    desc: '카이사르·비즈네르부터 Playfair·Hill·ADFGVX까지 — 치환·전치 암호 19종과 빈도 분석기',
    color: 'purple',
    tools: [
      {
        id: 'analyze', name: '빈도 분석 · 키 추정', short: 'IC · χ² · 비즈네르 키 길이',
        desc: '암호문의 문자 빈도와 일치 지수(IC)로 단일/다중 치환 여부를 판별하고, 카이사르 시프트와 비즈네르 키를 통계적으로 추정합니다.',
        modes: [{ id: 'run', label: '분석', inLabel: '암호문', placeholder: '영문 암호문 (길수록 정확합니다)' }],
        run: (s) => analyzeClassic(s),
      },
      {
        id: 'caesar', name: '카이사르 암호', short: '알파벳 시프트 · 전수 조사',
        desc: '알파벳을 일정한 칸만큼 밀어 치환합니다. 키를 모를 때는 "모든 시프트 보기"로 25가지 결과를 한 번에 확인하세요.',
        modes: ENC_DEC,
        options: [
          { id: 'shift', label: '시프트', type: 'number', default: 3, min: -25, max: 25 },
          { id: 'brute', label: '모든 시프트 보기', type: 'checkbox', default: false, mode: 'decode' },
        ],
        encode: (s, o) => caesar(s, Number(o.shift) || 0),
        decode: (s, o) => (o.brute
          ? Array.from({ length: 25 }, (_, i) => `ROT${String(i + 1).padStart(2, '0')}  ${caesar(s, -(i + 1))}`).join('\n')
          : caesar(s, -(Number(o.shift) || 0))),
      },
      { id: 'rot13', name: 'ROT13', short: '13칸 시프트 (대칭)', desc: '알파벳을 13칸 미는 카이사르 암호의 특수형입니다. 두 번 적용하면 원문으로 돌아옵니다.', modes: SYM, encode: (s) => caesar(s, 13) },
      { id: 'rot47', name: 'ROT47', short: 'ASCII 33–126 회전', desc: '알파벳뿐 아니라 숫자와 기호까지 포함한 94개 ASCII 문자를 47칸 회전합니다. 두 번 적용하면 원문입니다.', modes: SYM, encode: (s) => rot47(s) },
      { id: 'atbash', name: 'Atbash', short: 'A↔Z 거울 치환', desc: 'A는 Z로, B는 Y로 — 알파벳을 거꾸로 대응시키는 고대 히브리 암호입니다.', modes: SYM, encode: (s) => atbash(s) },
      {
        id: 'affine', name: 'Affine 암호', short: 'E(x) = (a·x + b) mod 26',
        desc: '곱셈과 덧셈을 결합한 단일 치환 암호입니다. a는 26과 서로소여야 복호화할 수 있습니다.',
        modes: ENC_DEC,
        options: [{ id: 'a', label: 'a', type: 'number', default: 5, min: 1, max: 25 }, { id: 'b', label: 'b', type: 'number', default: 8, min: 0, max: 25 }],
        encode: (s, o) => affine(s, o.a, o.b, 1),
        decode: (s, o) => affine(s, o.a, o.b, -1),
      },
      {
        id: 'substitution', name: '단일 치환 암호', short: '26글자 치환 알파벳',
        desc: 'A–Z를 임의의 순서로 섞은 치환 알파벳으로 한 글자씩 바꿉니다. 빈도 분석으로 풀 수 있는 대표적인 암호입니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '치환 알파벳', type: 'text', default: 'QWERTYUIOPASDFGHJKLZXCVBNM', wide: true }],
        encode: (s, o) => substitution(s, o.key, 1),
        decode: (s, o) => substitution(s, o.key, -1),
      },
      {
        id: 'vigenere', name: '비즈네르 암호', short: '키워드 다중 치환',
        desc: '키워드의 각 글자만큼 번갈아 시프트하는 다중 치환 암호입니다. 영문자가 아닌 문자는 그대로 두고 키도 넘기지 않습니다. 키를 모르면 "빈도 분석" 도구를 사용하세요.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
        encode: (s, o) => vigenere(s, o.key, 1),
        decode: (s, o) => vigenere(s, o.key, -1),
      },
      {
        id: 'beaufort', name: 'Beaufort 암호', short: 'C = K − P (대칭)',
        desc: '비즈네르의 변형으로, 키에서 평문을 뺍니다. 암호화와 복호화가 같은 연산입니다.',
        modes: SYM,
        options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
        encode: (s, o) => beaufort(s, o.key),
      },
      {
        id: 'autokey', name: 'Autokey 암호', short: '평문이 키 스트림이 됨',
        desc: '키워드 뒤에 평문 자체를 이어 붙여 키 스트림으로 씁니다. 키가 반복되지 않아 비즈네르의 키 길이 분석이 통하지 않습니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키', type: 'text', default: 'KEY' }],
        encode: (s, o) => autokey(s, o.key, 1),
        decode: (s, o) => autokey(s, o.key, -1),
      },
      {
        id: 'playfair', name: 'Playfair 암호', short: '5×5 행렬 · 두 글자 단위',
        desc: '키로 만든 5×5 표에서 두 글자씩 묶어 위치 규칙으로 치환합니다. J는 I로 합치고, 같은 글자가 연속되면 사이에 X를 넣습니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키', type: 'text', default: 'PLAYFAIR EXAMPLE' }],
        encode: (s, o) => playfair(s, o.key, 1),
        decode: (s, o) => playfair(s, o.key, -1),
      },
      {
        id: 'hill', name: 'Hill 암호', short: '2×2 / 3×3 행렬 곱',
        desc: '글자를 벡터로 보고 키 행렬을 곱하는 선형대수 기반 암호입니다. 키는 숫자 4/9개 또는 4/9글자 영단어(예: GYBNQKURP)로 입력합니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키 행렬', type: 'text', default: 'GYBNQKURP' }],
        encode: (s, o) => hill(s, o.key, 1),
        decode: (s, o) => hill(s, o.key, -1),
      },
      {
        id: 'polybius', name: 'Polybius 사각형', short: '글자 → 행·열 숫자',
        desc: '5×5 격자에서 각 글자를 행과 열 번호(11–55)로 바꿉니다. 탭 코드, Nihilist 암호 등의 기반입니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키 (선택)', type: 'text', default: '' }],
        encode: (s, o) => polybiusEnc(s, o.key),
        decode: (s, o) => polybiusDec(s, o.key),
      },
      {
        id: 'bifid', name: 'Bifid 암호', short: 'Polybius + 좌표 섞기',
        desc: '글자의 행 좌표와 열 좌표를 따로 모아 이어 붙인 뒤 다시 짝지어 치환과 전치를 동시에 수행합니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키', type: 'text', default: 'BGWKZQPNDSIOAXEFCLUMTHYVR' }, { id: 'period', label: '주기 (0=전체)', type: 'number', default: 0, min: 0, max: 100 }],
        encode: (s, o) => bifid(s, o.key, 1, o.period),
        decode: (s, o) => bifid(s, o.key, -1, o.period),
      },
      {
        id: 'adfgvx', name: 'ADFGVX 암호', short: '1차 대전 독일군 암호',
        desc: '6×6 격자로 글자를 ADFGVX 두 글자로 바꾼 뒤, 두 번째 키로 열 전치합니다. ADFGX(5×5) 변형도 지원합니다.',
        modes: ENC_DEC,
        options: [
          { id: 'variant', label: '종류', type: 'select', default: 'adfgvx', choices: [['adfgvx', 'ADFGVX (6×6)'], ['adfgx', 'ADFGX (5×5)']] },
          { id: 'square', label: '격자 키', type: 'text', default: 'PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8' },
          { id: 'trans', label: '전치 키', type: 'text', default: 'PRIVACY' },
        ],
        encode: (s, o) => adfgvx(s, o.square, o.trans, 1, o.variant),
        decode: (s, o) => adfgvx(s, o.square, o.trans, -1, o.variant),
      },
      {
        id: 'columnar', name: '열 전치 암호', short: '키워드 순서로 열 읽기',
        desc: '평문을 키 길이만큼의 행으로 나눠 적고, 키 글자의 알파벳 순서대로 열을 읽습니다. 공백도 한 글자로 취급합니다.',
        modes: ENC_DEC,
        options: [{ id: 'key', label: '키', type: 'text', default: 'ZEBRAS' }, { id: 'strip', label: '공백 제거', type: 'checkbox', default: true, mode: 'encode' }],
        encode: (s, o) => columnarEnc(o.strip ? s.replace(/\s/g, '') : s, o.key),
        decode: (s, o) => columnarDec(s, o.key),
      },
      {
        id: 'railfence', name: '레일펜스 암호', short: '지그재그 전치',
        desc: '글자를 여러 줄에 지그재그로 적은 뒤 줄 순서대로 읽는 전치 암호입니다.',
        modes: ENC_DEC,
        options: [{ id: 'rails', label: '레일 수', type: 'number', default: 3, min: 2, max: 50 }],
        encode: (s, o) => railEncode(s, Math.max(2, Number(o.rails) || 2)),
        decode: (s, o) => railDecode(s, Math.max(2, Number(o.rails) || 2)),
      },
      {
        id: 'bacon', name: 'Bacon 암호', short: 'A/B 5비트 · 대소문자 은닉',
        desc: '글자를 A와 B 다섯 개의 패턴으로 바꿉니다. 디코딩 시 0/1이나, 일반 문장의 소문자(A)/대문자(B) 패턴으로 숨긴 메시지도 인식합니다.',
        modes: ENC_DEC,
        options: [{ id: 'variant', label: '알파벳', type: 'select', default: '26', choices: [['26', '26글자'], ['24', '24글자 (I=J, U=V)']] }],
        encode: (s, o) => baconEnc(s, o.variant),
        decode: (s, o) => baconDec(s, o.variant),
      },
      {
        id: 'xor', name: 'XOR', short: '반복 키 XOR · Hex 출력',
        desc: '입력 바이트를 키와 반복 XOR합니다. 결과는 바이너리이므로 암호화 출력과 복호화 입력은 16진수를 사용합니다. 키를 모르면 "바이너리 분석 → XOR 전수 조사"를 사용하세요.',
        modes: ENC_DEC,
        options: [
          { id: 'key', label: '키', type: 'text', default: 'secret' },
          { id: 'keyType', label: '키 형식', type: 'select', default: 'text', choices: [['text', '텍스트'], ['hex', '16진수']] },
        ],
        encode: (s, o) => toHex(xorBytes(utf8(s), xorKey(o)), false, ' '),
        decode: (s, o) => xorBytes(fromHex(s), xorKey(o)),
      },
      {
        id: 'morse', name: '모스 부호', short: '. - / 표기',
        desc: '문자는 공백으로, 단어는 / 로 구분합니다. 디코딩 시 · 와 _ 같은 변형 기호도 인식합니다.',
        encode: (s) => morseEncode(s),
        decode: (s) => morseDecode(s),
      },
    ],
  });
})(globalThis.DecryptLab);
