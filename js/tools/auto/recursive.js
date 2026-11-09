/* 자동 분석 › 재귀 디코더 */
(function (DL) {
  'use strict';
  const K = DL.kits.auto;
  const { utf8, utf8Decode, b64decode, fromHex, textScore, fn } = K;

  // 각 단계: 현재 바이트를 텍스트로 보고 디코더를 모두 시도한 뒤, 가장 읽기 좋은 결과 하나를 채택한다.
  const STEPS = [
    ['Gzip/Zlib 해제', (t, b) => (b[0] === 0x1f && b[1] === 0x8b) || (((b[0] & 0x0f) === 8) && ((b[0] << 8) | b[1]) % 31 === 0 && b.length > 2), async (t, b) => (await fn.decompress(b, 'auto')).out, 3],
    ['Base64', (t) => /^[A-Za-z0-9+/_\-\s]+={0,2}$/.test(t) && t.replace(/\s/g, '').length >= 4, (t) => b64decode(t), 2],
    ['16진수(Hex)', (t) => /^((0x|\\x)?[0-9a-f]{2}[\s:,]*)+$/i.test(t), (t) => fromHex(t), 2.5],
    ['Base32', (t) => /^[A-Z2-7\s]+=*$/.test(t) && t.replace(/[\s=]/g, '').length >= 8, (t) => fn.b32decode(t), 1.5],
    ['Base58', (t) => /^[1-9A-HJ-NP-Za-km-z]{6,}$/.test(t), (t) => fn.b58decode(t), 1],
    ['Ascii85', (t) => /^<~[\s\S]*~>$/.test(t), (t) => fn.a85decode(t), 3],
    ['2진수', (t) => /^[01\s]+$/.test(t) && t.replace(/\s/g, '').length % 8 === 0, (t) => fn.radixDecode(t, 2), 3],
    ['10진수 바이트', (t) => /^\d{1,3}([\s,]+\d{1,3})+$/.test(t), (t) => fn.radixDecode(t, 10), 2],
    ['URL 디코딩', (t) => /%[0-9a-f]{2}/i.test(t), (t) => fn.urlDecode(t, { plus: true }), 3],
    ['HTML 엔티티', (t) => /&(#x?[0-9a-f]+|[a-z]+);/i.test(t), (t) => utf8(fn.htmlDecode(t)), 3],
    ['유니코드 이스케이프', (t) => /\\u[0-9a-f{]/i.test(t), (t) => utf8(fn.uniDecode(t)), 3],
    ['\\x 바이트 이스케이프', (t) => /\\x[0-9a-f]{2}/i.test(t), (t) => fn.jsUnescape(t, { xmode: 'byte' }), 3],
    ['Quoted-Printable', (t) => /=[0-9A-F]{2}/.test(t) && !/[^\x20-\x7e\r\n]/.test(t), (t) => fn.qpDecode(t), 1],
  ];
  const isGz = (b) => (b[0] === 0x1f && b[1] === 0x8b);
  const toHexKey = (b) => (b.length > 4096 ? `${b.length}:${DL.toHex(b.subarray(0, 64))}${DL.toHex(b.subarray(-64))}` : DL.toHex(b));
  async function recursiveDecode(input, { maxDepth = 15 } = {}) {
    let bytes = utf8(input.trim());
    const steps = [];
    const seen = new Set([toHexKey(bytes)]);
    for (let depth = 0; depth < maxDepth; depth++) {
      let text = '';
      try { text = utf8Decode(bytes, true).trim(); } catch { text = ''; }
      let best = null;
      for (const [name, test, decode, prio] of STEPS) {
        if (!test(text, bytes)) continue;
        let out;
        try { out = await decode(text, bytes); } catch { continue; }
        if (!out || !out.length || seen.has(toHexKey(out))) continue;
        const readable = textScore(out);
        const score = isGz(out) ? 0.97 : readable;
        if (score < 0.9) continue;
        const rank = score * 10 + prio;
        if (!best || rank > best.rank) best = { name, out, rank };
      }
      if (!best) break;
      seen.add(toHexKey(best.out));
      steps.push({ name: best.name, out: best.out });
      bytes = best.out;
    }
    if (!steps.length) return '디코딩할 수 있는 인코딩을 찾지 못했습니다. 이미 평문이거나, 키가 필요한 암호문일 수 있습니다.\n→ "인코딩 자동 감지"나 "바이너리 분석 › 엔트로피 분석"으로 확인해 보세요.';
    const preview = (b) => { try { const t = utf8Decode(b, true); return t.length > 160 ? t.slice(0, 160) + ' …' : t; } catch { return `(바이너리 ${b.length} B)`; } };
    const lines = steps.map((s, i) => `${String(i + 1).padStart(2)}. ${s.name.padEnd(14)} → ${preview(s.out).replace(/\n/g, '⏎')}`);
    let final;
    try { final = utf8Decode(bytes, true); } catch { final = DL.toHex(bytes, false, ' '); }
    return `■ 디코딩 경로 (${steps.length}단계): ${steps.map((s) => s.name).join(' → ')}\n\n${lines.join('\n')}\n\n■ 최종 결과\n${final}`;
  }
  K.recursiveDecode = recursiveDecode;
  DL.fn.recursiveDecode = recursiveDecode;

  DL.addTool('auto', {
    id: 'recursive', name: '재귀 디코더', short: '중첩된 인코딩을 끝까지 자동 해제',
    desc: 'Base64 → Hex → URL 인코딩 → Gzip처럼 여러 겹으로 감싼 데이터를 읽을 수 있는 결과가 나올 때까지 반복해서 풉니다. 각 단계에서 가장 읽기 좋은 결과를 고르며, 거쳐 간 경로를 함께 보여줍니다.',
    slow: true,
    modes: [{ id: 'run', label: '자동 해제', inLabel: '인코딩된 값', outLabel: '디코딩 경로와 결과' }],
    options: [{ id: 'maxDepth', label: '최대 단계', type: 'number', default: 15, min: 1, max: 50 }],
    run: (s, o) => recursiveDecode(s, { maxDepth: Math.min(50, Number(o.maxDepth) || 15) }),
  });
})(globalThis.DecryptLab);
