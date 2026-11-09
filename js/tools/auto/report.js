/* 자동 분석 › 종합 분석 리포트
 * autoDetect·identifyHash·recursiveDecode·PATTERNS는 다른 도구 파일이 DL.kits.auto에 등록한다.
 * 이 리포트는 실행 시점(사용자 클릭)에 그 함수들을 꺼내 쓴다. */
(function (DL) {
  'use strict';
  const K = DL.kits.auto;
  const { utf8, b64decode, fromHex, textScore, fn } = K;

  const toolPath = (c, t) => {
    const cat = DL.CATEGORIES.find((x) => x.id === c);
    const tool = cat && cat.tools.find((x) => x.id === t);
    return tool ? `${cat.name} › ${tool.name}` : null;
  };
  const CONF = { 3: '높음', 2: '중간', 1: '낮음' };
  const COMMON = new Set('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were has had been flag key secret password hello world message text'.split(' '));

  async function analysisReport(input) {
    const s = input.trim();
    if (!s) return '';
    const { autoDetect, identifyHash, recursiveDecode, PATTERNS } = K;
    const raw = utf8(s);
    const findings = [];
    const add = (conf, what, why, extra = {}) => findings.push({ conf, what, why, ...extra });

    // 1) 개요
    const isHex = /^((0x|\\x)?[0-9a-f]{2}[\s:,]*)+$/i.test(s);
    const isB64 = /^[A-Za-z0-9+/_\-\s]+={0,2}$/.test(s) && s.replace(/\s/g, '').length % 4 !== 1;
    const letters = (s.match(/[A-Za-z]/g) || []).length;
    const charset = isHex ? '16진수 문자만 (0–9, a–f)' : isB64 ? 'Base64 문자 집합' : /^[\x20-\x7e\r\n\t]+$/.test(s) ? '출력 가능한 ASCII' : '비ASCII 문자 포함 (한글 등)';
    let decoded = null, decodedBy = '';
    try { if (isHex) { decoded = fromHex(s); decodedBy = '16진수'; } else if (isB64) { decoded = b64decode(s); decodedBy = 'Base64'; } } catch { decoded = null; }
    const overview = [`길이        ${Array.from(s).length.toLocaleString()}자 · ${raw.length.toLocaleString()} B`, `문자 구성   ${charset}`, `엔트로피    ${DL.entropy(raw).toFixed(2)} 비트/문자`];
    if (decoded) overview.push(`${decodedBy} 디코딩 시 ${decoded.length.toLocaleString()} B · 엔트로피 ${DL.entropy(decoded).toFixed(2)} 비트/바이트`);

    // 2) 구조적 형식 (확실한 신호)
    if (/^-----BEGIN [A-Z0-9 ]+-----/.test(s)) add(3, 'PEM (키 또는 인증서)', 'BEGIN/END 경계선이 있습니다.', { tools: [toolPath('token', 'x509'), toolPath('token', 'asn1')] });
    const dots = s.split('.');
    if (/^eyJ/.test(s) && dots.length === 3) add(3, 'JWT (서명된 토큰)', 'Base64URL JSON 헤더(eyJ…)와 점 2개로 구성됩니다.', { need: '서명 검증에는 비밀키나 공개키가 필요합니다. 내용 확인에는 키가 필요 없습니다.', tools: [toolPath('token', 'jwt'), toolPath('token', 'jwtverify')] });
    if (/^eyJ/.test(s) && dots.length === 5) add(3, 'JWE (암호화된 토큰)', '점 4개로 나뉜 5개 부분입니다.', { need: '복호화 키(RSA 개인키 또는 대칭키)가 필요합니다.', tools: [toolPath('token', 'jwe')] });
    if (/^U2FsdGVkX1/.test(s)) add(3, 'OpenSSL·CryptoJS 비밀번호 암호문', 'Base64 "Salted__" 헤더(U2FsdGVkX1)로 시작합니다.', { need: '암호화에 쓴 비밀번호가 필요합니다.', tools: [toolPath('symmetric', 'openssl')] });
    if (/^data:[^,]*,/.test(s)) add(3, 'Data URI', 'data: 스킴으로 시작합니다.', { tools: [toolPath('binary', 'datauri')] });
    if (/(SAMLRequest|SAMLResponse)=/.test(s)) add(3, 'SAML 메시지', 'SAML 파라미터가 포함되어 있습니다.', { tools: [toolPath('token', 'saml')] });

    // 3) 해시 형식
    const hashLines = identifyHash(s).split('\n');
    const hashTop = hashLines.find((l) => l.includes('가장 유력'));
    if (hashTop && !s.includes('\n')) {
      const name = hashTop.replace(/.*가장 유력\s+/, '');
      const strong = PATTERNS.some(([re]) => re.test(s));
      add(strong ? 3 : 2, `해시값 — ${name}`, strong ? '해시 형식 고유의 접두사·구조가 있습니다.' : '길이와 문자 구성이 해시와 일치합니다. 같은 길이의 다른 데이터(키, 암호문)일 수도 있습니다.',
        { need: '해시는 복호화할 수 없습니다. 후보 평문을 해시해서 비교하는 방식으로만 확인할 수 있습니다.', tools: [toolPath('auto', 'hashid'), toolPath('hash', 'hash')] });
    }

    // 4) 인코딩 — 재귀 디코더로 끝까지 풀어 본다
    const rec = await recursiveDecode(s);
    const path = /디코딩 경로 \((\d+)단계\): (.*)/.exec(rec);
    if (path) {
      const final = rec.split('■ 최종 결과\n')[1] || '';
      add(Number(path[1]) > 1 ? 3 : 2.5, Number(path[1]) > 1 ? `중첩 인코딩 (${path[1]}겹)` : `인코딩 — ${path[2]}`, `${path[2]} 순서로 풀면 읽을 수 있는 결과가 나옵니다.`,
        { result: final.length > 300 ? final.slice(0, 300) + ' …' : final, tools: [toolPath('auto', 'recursive')] });
    }

    // 5) 디코딩해도 읽을 수 없는 바이너리 → 파일/압축/암호문
    if (decoded && decoded.length && textScore(decoded) < 0.9) {
      const magic = fn.identifyMagic ? fn.identifyMagic(decoded) : [];
      const h = DL.entropy(decoded);
      if (magic.length) add(3, `${decodedBy}로 감싼 파일 — ${magic[0].name}`, `디코딩한 바이트가 ${magic[0].name} 시그니처로 시작합니다.`, { tools: [toolPath('binary', 'magic'), magic[0].ext === 'gz' || magic[0].ext === 'zlib' ? toolPath('compress', 'deflate') : magic[0].ext === 'zip' ? toolPath('compress', 'zip') : toolPath('binary', 'hexview')].filter(Boolean) });
      else if (h > 6.5 || (decoded.length < 256 && h > 4.5)) {
        if (decoded.length % 16 === 0) add(2, '블록 암호문 가능성 (AES·ARIA·SEED 등)', `${decodedBy} 디코딩 결과가 무작위적이고(엔트로피 ${h.toFixed(2)}) 길이 ${decoded.length} B가 16의 배수입니다.`,
          { need: '키, 운용 모드(CBC·GCM 등), IV가 필요합니다. IV가 암호문 앞 16 B에 붙어 있는 경우가 많습니다.', tools: [toolPath('symmetric', 'aes'), toolPath('symmetric', 'aria'), toolPath('symmetric', 'seed')] });
        else add(1.5, '스트림 암호문 또는 XOR 가능성', `무작위적이지만 길이(${decoded.length} B)가 블록 크기의 배수가 아닙니다. RC4·ChaCha20·CTR/GCM 모드·XOR일 수 있습니다.`,
          { need: '키(와 nonce)가 필요합니다.', tools: [toolPath('symmetric', 'rc4'), toolPath('symmetric', 'chacha20'), toolPath('binary', 'xorbrute')] });
      } else if (!xorFinding(decoded)) {
        add(1, '구조가 있는 바이너리', `엔트로피 ${h.toFixed(2)} — 암호문보다는 실행 파일·데이터 파일 일부에 가깝습니다.`, { tools: [toolPath('binary', 'hexview'), toolPath('binary', 'strings')] });
      }
    } else if (decoded && decoded.length >= 8) xorFinding(decoded);

    // 단일 바이트 XOR: 원래 바이트보다 XOR 결과가 훨씬 영어다우면 후보로 올린다
    function xorFinding(bytes) {
      if (!fn.xorBrute) return false;
      const m = /키 0x([0-9a-f]{2}).*점수 (-?[\d.]+)\n([\s\S]*)/.exec(fn.xorBrute(bytes, { top: 1 }));
      if (!m || m[1] === '00' || Number(m[2]) < 1.2 || Number(m[2]) < fn.englishScore(bytes) + 0.8) return false;
      add(2.8, `단일 바이트 XOR (키 0x${m[1]})`, `${decodedBy} 디코딩 결과를 한 바이트 키 0x${m[1]}로 XOR하면 영어 문장에 가까워집니다.`, { result: m[3].slice(0, 200), tools: [toolPath('binary', 'xorbrute')] });
      return true;
    }

    // 6) 영문자 위주 → 고전 암호
    if (!findings.some((f) => f.conf >= 2.5) && letters >= 20 && letters / s.replace(/\s/g, '').length > 0.85) {
      const ic = fn.ioc(s);
      const { shift } = fn.bestShift(s);
      const words = (t) => (t.toLowerCase().match(/[a-z]+/g) || []).filter((w) => COMMON.has(w)).length;
      const shifted = fn.caesar(s, -shift);
      if (shift && words(shifted) >= 2 && words(shifted) > words(s)) {
        add(2.8, `카이사르 암호 (시프트 ${shift})`, `${shift}칸 되돌리면 흔한 영어 단어가 ${words(shifted)}개 나타납니다.`, { result: shifted.slice(0, 200), tools: [toolPath('classic', 'caesar')] });
      } else if (ic > 0.058) {
        const { shift } = fn.bestShift(s);
        add(shift ? 2 : 1, shift ? `카이사르 암호 (시프트 ${shift}) 가능성` : '평문 영어 또는 전치 암호', `일치 지수(IC) ${ic.toFixed(3)}가 영어(≈0.066)에 가깝습니다 — 단일 치환이나 전치 암호의 특징입니다.`,
          { result: shift ? fn.caesar(s, -shift).slice(0, 200) : undefined, tools: [toolPath('classic', 'analyze'), toolPath('classic', 'caesar')] });
      } else if (ic < 0.05) add(1.5, '다중 치환 암호 (비즈네르 계열) 가능성', `일치 지수(IC) ${ic.toFixed(3)}가 낮습니다 — 키워드를 쓰는 다중 치환 암호의 특징입니다.`,
        { need: '키워드가 필요합니다. 빈도 분석 도구로 키 길이와 키를 추정해 볼 수 있습니다.', tools: [toolPath('classic', 'analyze'), toolPath('classic', 'vigenere')] });
    }

    // 7) 그 밖의 디코딩 후보
    const cands = autoDetect(s, true).filter((c) => !findings.some((f) => f.result && f.result.startsWith(c.out.slice(0, 50))));
    if (!findings.length && !cands.length) add(1, '판별 불가', '알려진 인코딩·형식과 일치하지 않습니다. 평문이거나, 키가 필요한 암호문이거나, 이 도구가 지원하지 않는 형식일 수 있습니다.', { tools: [toolPath('binary', 'entropy')] });

    findings.sort((a, b) => b.conf - a.conf);
    const out = ['■ 데이터 개요', ...overview.map((l) => '  ' + l), '', '■ 유형 추정 (신뢰도순)'];
    findings.forEach((f, i) => {
      out.push(`  ${i + 1}. [${CONF[Math.round(f.conf)] || '낮음'}] ${f.what}`, `     근거  ${f.why}`);
      if (f.need) out.push(`     필요  ${f.need}`);
      if (f.result) out.push(`     결과  ${f.result.replace(/\n/g, '\n           ')}`);
      if (f.tools && f.tools.filter(Boolean).length) out.push(`     도구  ${f.tools.filter(Boolean).join('  ·  ')}`);
      out.push('');
    });
    if (cands.length) {
      out.push('■ 기타 디코딩 후보');
      cands.slice(0, 3).forEach((c) => out.push(`  · ${c.name} (가독성 ${(c.score * 100).toFixed(0)}%)  ${c.out.slice(0, 120).replace(/\n/g, '⏎')}`));
      out.push('');
    }
    out.push('※ 형식과 통계로 추정한 결과입니다. "높음"도 확정이 아니며, 실제 알고리즘·키는 출처 정보와 함께 판단하세요.');
    return out.join('\n');
  }
  DL.fn.analysisReport = analysisReport;

  DL.addTool('auto', {
    id: 'report', name: '종합 분석 리포트', short: '유형 추정 · 후보 · 필요한 키 · 다음 단계',
    desc: '정체 모를 값을 넣으면 데이터 특성(문자 구성, 엔트로피), 가능한 형식과 신뢰도, 디코딩 결과, 복호화에 필요한 키·파라미터, 이어서 쓸 도구를 한 번에 정리합니다.',
    slow: true,
    modes: [{ id: 'run', label: '분석', inLabel: '분석할 값', outLabel: '분석 리포트' }],
    run: (s) => analysisReport(s),
  });
})(globalThis.DecryptLab);
