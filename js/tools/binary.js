/* 바이너리 분석 */
(function (DL) {
  'use strict';
  const { utf8Decode, toHex, fromHex, readBytes, fmtOption, entropy, b64decode, printableScore } = DL;

  /* ---------- 파일 시그니처 ---------- */
  // [오프셋, 16진수 시그니처, 이름, 확장자, 설명]
  const SIGS = [
    [0, '89504e470d0a1a0a', 'PNG 이미지', 'png'], [0, 'ffd8ff', 'JPEG 이미지', 'jpg'], [0, '47494638', 'GIF 이미지', 'gif'],
    [0, '424d', 'BMP 이미지', 'bmp', '약한 시그니처'], [0, '49492a00', 'TIFF 이미지 (LE)', 'tif'], [0, '4d4d002a', 'TIFF 이미지 (BE)', 'tif'],
    [0, '00000100', 'ICO 아이콘', 'ico'], [8, '57454250', 'WebP 이미지', 'webp'], [0, '3c737667', 'SVG 이미지', 'svg'],
    [0, '25504446', 'PDF 문서', 'pdf'], [0, 'd0cf11e0a1b11ae1', 'MS Office 97–2003 / OLE (doc·xls·ppt·msi)', 'doc'],
    [0, '504b0304', 'ZIP 압축 (docx·xlsx·pptx·jar·apk 포함)', 'zip'], [0, '504b0506', '빈 ZIP 압축', 'zip'], [0, '504b0708', '분할 ZIP 압축', 'zip'],
    [0, '1f8b', 'Gzip 압축', 'gz'], [0, '425a68', 'Bzip2 압축', 'bz2'], [0, 'fd377a585a00', 'XZ 압축', 'xz'],
    [0, '377abcaf271c', '7-Zip 압축', '7z'], [0, '526172211a07', 'RAR 압축', 'rar'], [0, '28b52ffd', 'Zstandard 압축', 'zst'],
    [0, '04224d18', 'LZ4 프레임', 'lz4'], [0, '4d534346', 'Microsoft CAB', 'cab'], [0, '1f9d', 'Unix compress (.Z)', 'z'],
    [257, '7573746172', 'TAR 아카이브', 'tar'], [0, '213c617263683e', 'ar 아카이브 / Debian 패키지', 'deb'], [0, 'edabeedb', 'RPM 패키지', 'rpm'],
    [0, '7f454c46', 'ELF 실행 파일 (Linux)', 'elf'], [0, '4d5a', 'PE/MZ 실행 파일 (Windows exe·dll)', 'exe'],
    [0, 'cafebabe', 'Java class 또는 Mach-O Universal', 'class'], [0, 'feedface', 'Mach-O 32비트 (BE)', 'macho'], [0, 'feedfacf', 'Mach-O 64비트 (BE)', 'macho'],
    [0, 'cefaedfe', 'Mach-O 32비트', 'macho'], [0, 'cffaedfe', 'Mach-O 64비트 (macOS)', 'macho'], [0, '6465780a', 'Android DEX', 'dex'],
    [0, '0061736d', 'WebAssembly', 'wasm'], [0, '2321', '스크립트 (shebang)', 'sh'], [0, '4c0000000114020000000000c000000000000046', 'Windows 바로가기', 'lnk'],
    [0, '53514c69746520666f726d6174203300', 'SQLite 데이터베이스', 'sqlite'], [0, 'd4c3b2a1', 'PCAP 패킷 캡처 (LE)', 'pcap'], [0, 'a1b2c3d4', 'PCAP 패킷 캡처 (BE)', 'pcap'],
    [0, '0a0d0d0a', 'PCAPNG 패킷 캡처', 'pcapng'], [0, '2d2d2d2d2d424547494e', 'PEM (키·인증서)', 'pem'], [0, '3082', 'DER (ASN.1 — 인증서·키 가능성)', 'der', '약한 시그니처'],
    [0, '494433', 'MP3 (ID3 태그)', 'mp3'], [0, 'fffb', 'MP3 오디오', 'mp3'], [8, '57415645', 'WAV 오디오', 'wav'], [8, '41564920', 'AVI 동영상', 'avi'],
    [4, '66747970', 'MP4 / MOV / HEIC (ISO BMFF)', 'mp4'], [0, '1a45dfa3', 'MKV / WebM', 'mkv'], [0, '4f676753', 'OGG 미디어', 'ogg'], [0, '664c6143', 'FLAC 오디오', 'flac'],
    [0, '774f4646', 'WOFF 폰트', 'woff'], [0, '774f4632', 'WOFF2 폰트', 'woff2'], [0, '00010000', 'TrueType 폰트', 'ttf', '약한 시그니처'], [0, '4f54544f', 'OpenType 폰트', 'otf'],
    [0, '3c3f786d6c', 'XML 문서', 'xml'], [0, 'efbbbf', 'UTF-8 BOM 텍스트', 'txt'], [0, 'fffe', 'UTF-16LE BOM 텍스트', 'txt'], [0, 'feff', 'UTF-16BE BOM 텍스트', 'txt'],
    [0, '53616c7465645f5f', 'OpenSSL enc 암호문 (Salted__)', 'enc'], [0, '89484446', 'HDF5 데이터', 'h5'], [0, '7b5c727466', 'RTF 문서', 'rtf'],
  ].map(([off, hex, name, ext, note]) => ({ off, sig: fromHex(hex), name, ext, note }));
  function identifyMagic(bytes) {
    const hits = SIGS.filter(({ off, sig }) => bytes.length >= off + sig.length && sig.every((b, i) => bytes[off + i] === b));
    if (bytes.length >= 2 && (bytes[0] & 0x0f) === 8 && ((bytes[0] << 8) | bytes[1]) % 31 === 0 && (bytes[0] >> 4) <= 7) {
      hits.push({ name: 'Zlib 압축 스트림', ext: 'zlib', note: '헤더 체크섬 일치' });
    }
    return hits.sort((a, b) => b.sig?.length - a.sig?.length || 0);
  }

  /* ---------- 헥스 뷰 ---------- */
  const asciiChar = (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.');
  function hexdump(bytes, { width = 16, start = 0, max = 65536 } = {}) {
    const end = Math.min(bytes.length, start + max);
    const lines = [];
    for (let i = start; i < end; i += width) {
      const row = bytes.subarray(i, Math.min(i + width, end));
      const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0'));
      const groups = [];
      for (let g = 0; g < width; g += 8) groups.push(hex.slice(g, g + 8).join(' ').padEnd(8 * 3 - 1));
      lines.push(`${i.toString(16).padStart(8, '0')}  ${groups.join('  ')}  |${Array.from(row, asciiChar).join('')}|`);
    }
    if (end < bytes.length) lines.push('', `… ${(bytes.length - end).toLocaleString()} B 더 있음 (시작 오프셋을 바꿔서 이어 볼 수 있습니다)`);
    return lines.join('\n');
  }

  /* ---------- 엔트로피 ---------- */
  const BARS = '▁▂▃▄▅▆▇█';
  function entropyReport(bytes) {
    if (!bytes.length) throw new Error('분석할 데이터가 없습니다.');
    const h = entropy(bytes);
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const unique = freq.filter(Boolean).length;
    const printable = bytes.filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13).length / bytes.length;
    const nulls = freq[0] / bytes.length;
    const expected = bytes.length / 256;
    const chi = freq.reduce((a, f) => a + ((f - expected) ** 2) / expected, 0);
    let verdict;
    if (printable > 0.95) verdict = h > 5.6 ? 'Base64/Hex 같은 인코딩된 텍스트일 가능성이 높습니다.' : '일반 텍스트로 보입니다.';
    else if (h > 7.9) verdict = '매우 무작위적입니다 — 암호화되었거나 압축된 데이터일 가능성이 높습니다.';
    else if (h > 7.2) verdict = '무작위성이 높습니다 — 압축 데이터, 암호문, 또는 미디어 파일일 수 있습니다.';
    else if (h > 5) verdict = '구조가 있는 바이너리(실행 파일, 데이터 파일 등)로 보입니다.';
    else verdict = '반복이 많은 데이터입니다 — 텍스트, 패딩, 또는 단순 XOR 데이터일 수 있습니다.';

    const lines = [
      `크기             ${bytes.length.toLocaleString()} B`,
      `엔트로피         ${h.toFixed(4)} 비트/바이트  (최대 8)`,
      `서로 다른 바이트 ${unique} / 256`,
      `출력 가능 문자   ${(printable * 100).toFixed(1)}%`,
      `0x00 비율        ${(nulls * 100).toFixed(1)}%`,
      `카이제곱(균등)   ${chi.toFixed(1)}  ${bytes.length >= 2560 ? (chi < 330 ? '(균등 분포에 가까움 — 암호문 특징)' : '(균등하지 않음)') : '(데이터가 적어 판단 어려움)'}`,
      '', `판단: ${verdict}`,
    ];
    if (bytes.length >= 512) {
      const blocks = Math.min(64, Math.floor(bytes.length / 64));
      const size = Math.ceil(bytes.length / blocks);
      const hs = [];
      for (let i = 0; i < bytes.length; i += size) hs.push(entropy(bytes.subarray(i, i + size)));
      lines.push('', `■ 구간별 엔트로피 (${size.toLocaleString()} B 단위, 0–8)`, '  ' + hs.map((v) => BARS[Math.min(7, Math.floor(v))]).join(''));
      lines.push('  구간 사이 엔트로피 차이가 크면 암호화·압축된 영역이 섞여 있다는 뜻입니다.');
    }
    const top = freq.map((f, b) => [b, f]).sort((a, b) => b[1] - a[1]).slice(0, 8);
    lines.push('', '■ 가장 많은 바이트');
    for (const [b, f] of top) if (f) lines.push(`  0x${b.toString(16).padStart(2, '0')} ${asciiChar(b) === '.' ? ' ' : `'${asciiChar(b)}'`}  ${((f / bytes.length) * 100).toFixed(2)}%`);
    return lines.join('\n');
  }

  /* ---------- 문자열 추출 ---------- */
  function extractStrings(bytes, { min = 4, enc = 'both', limit = 5000 } = {}) {
    const found = [];
    const isP = (b) => b >= 32 && b < 127;
    if (enc !== 'utf16') {
      let start = -1;
      for (let i = 0; i <= bytes.length; i++) {
        if (i < bytes.length && isP(bytes[i])) { if (start < 0) start = i; }
        else if (start >= 0) {
          if (i - start >= min) found.push([start, 'A', DL.latin1(bytes.subarray(start, i))]);
          start = -1;
        }
      }
    }
    if (enc !== 'ascii') {
      for (const phase of [0, 1]) {
        let start = -1, s = '';
        for (let i = phase; i + 1 <= bytes.length; i += 2) {
          if (i + 1 < bytes.length && isP(bytes[i]) && bytes[i + 1] === 0) { if (start < 0) start = i; s += String.fromCharCode(bytes[i]); }
          else { if (start >= 0 && s.length >= min) found.push([start, 'W', s]); start = -1; s = ''; }
        }
      }
    }
    found.sort((a, b) => a[0] - b[0]);
    const out = found.slice(0, limit).map(([off, t, s]) => `${off.toString(16).padStart(8, '0')}  ${t}  ${s}`);
    if (!out.length) return `길이 ${min} 이상의 문자열을 찾지 못했습니다.`;
    return `${found.length.toLocaleString()}개 발견 (A = ASCII, W = UTF-16LE)${found.length > limit ? ` · 처음 ${limit}개만 표시` : ''}\n\n${out.join('\n')}`;
  }

  /* ---------- XOR 전수 조사 ---------- */
  const EN = 'etaoin shrdlu';
  function englishScore(bytes) {
    let score = 0;
    for (const b of bytes) {
      if (b === 32) score += 3;
      else if ((b >= 97 && b <= 122) || (b >= 65 && b <= 90)) score += EN.includes(String.fromCharCode(b | 32)) ? 2 : 1;
      else if (b >= 48 && b <= 57) score += 0.5;
      else if (b === 10 || b === 13 || b === 9 || (b >= 33 && b < 127)) score += 0;
      else score -= 6;
    }
    return score / bytes.length;
  }
  function xorBrute(bytes, { crib = '', top = 10 } = {}) {
    if (!bytes.length) throw new Error('분석할 데이터가 없습니다.');
    const cribLow = crib.toLowerCase();
    const results = [];
    for (let k = 0; k < 256; k++) {
      const out = bytes.map((b) => b ^ k);
      const text = DL.latin1(out);
      if (crib && !text.toLowerCase().includes(cribLow)) continue;
      results.push({ k, score: englishScore(out), text });
    }
    if (!results.length) return `"${crib}"를 포함하는 단일 바이트 XOR 결과가 없습니다. 키가 여러 바이트일 수 있습니다.`;
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, Number(top) || 10).map(({ k, score, text }, i) => {
      const preview = text.replace(/[^\x20-\x7e\n]/g, '·');
      return `[${i + 1}] 키 0x${k.toString(16).padStart(2, '0')} ('${asciiChar(k)}')  점수 ${score.toFixed(2)}\n${preview.length > 400 ? preview.slice(0, 400) + ' …' : preview}`;
    }).join('\n\n');
  }

  /* ---------- Data URI ---------- */
  function parseDataUri(s) {
    const m = /^data:([^,]*?),([\s\S]*)$/i.exec(s.trim());
    if (!m) throw new Error('"data:[MIME 타입][;base64],데이터" 형식이 아닙니다.');
    const params = m[1].split(';').filter(Boolean);
    const isB64 = params.some((p) => p.toLowerCase() === 'base64');
    const mime = params.find((p) => p.includes('/')) || 'text/plain (기본값)';
    const charset = (params.find((p) => /^charset=/i.test(p)) || '').split('=')[1];
    const bytes = isB64 ? b64decode(decodeURIComponent(m[2])) : DL.fn.urlDecode(m[2]);
    const magic = identifyMagic(bytes);
    const lines = [
      `MIME 타입   ${mime}`, `인코딩      ${isB64 ? 'Base64' : 'URL 퍼센트 인코딩'}`, charset ? `문자셋      ${charset}` : '',
      `디코딩 크기 ${bytes.length.toLocaleString()} B`, `실제 형식   ${magic.length ? magic.map((x) => x.name).join(', ') : '알 수 없음'}`,
    ].filter(Boolean);
    if (magic.length && !mime.includes(magic[0].ext) && !mime.includes('plain')) lines.push('', `⚠ 선언된 MIME 타입과 실제 시그니처가 다를 수 있습니다.`);
    let text = null;
    try { text = utf8Decode(bytes, true); } catch { /* 바이너리 */ }
    if (text !== null && printableScore(text) > 0.9) lines.push('', '■ 내용 (텍스트)', text.length > 5000 ? text.slice(0, 5000) + '\n…' : text);
    else lines.push('', '■ 내용 (헥스 덤프, 처음 512 B)', hexdump(bytes, { max: 512 }));
    return lines.join('\n');
  }

  Object.assign(DL.fn, { identifyMagic, hexdump, entropyReport, extractStrings, xorBrute, englishScore });

  const IN = (def) => fmtOption('inFmt', '입력 형식', def, ['text', 'hex', 'base64']);

  DL.addCategory({
    id: 'binary',
    name: '바이너리 분석',
    desc: '파일과 바이트를 직접 들여다보는 도구 — 헥스 뷰어, 파일 시그니처, 엔트로피, 문자열 추출, XOR 전수 조사',
    color: 'cyan',
    tools: [
      {
        id: 'hexview', name: '헥스 뷰어', short: '오프셋 · 16진수 · ASCII',
        desc: '바이트를 오프셋, 16진수, ASCII로 나란히 보여줍니다. "파일 열기"로 실제 파일을 열 수 있으며, 한 번에 최대 64 KB를 표시합니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '보기', inLabel: '데이터', outLabel: '헥스 덤프' }],
        options: [
          IN('text'),
          { id: 'width', label: '한 줄 바이트', type: 'select', default: '16', choices: [['8', '8'], ['16', '16'], ['32', '32']] },
          { id: 'start', label: '시작 오프셋 (16진)', type: 'text', default: '0' },
        ],
        run: (s, o) => {
          const bytes = readBytes(s, o.inFmt);
          const start = parseInt(o.start || '0', 16);
          if (!Number.isFinite(start) || start < 0) throw new Error('시작 오프셋은 16진수여야 합니다.');
          if (start >= bytes.length && bytes.length) throw new Error(`시작 오프셋이 데이터 크기(0x${bytes.length.toString(16)})를 넘습니다.`);
          return hexdump(bytes, { width: Number(o.width), start });
        },
      },
      {
        id: 'magic', name: '파일 시그니처 판별', short: '매직 바이트로 형식 추정',
        desc: '파일 앞부분의 매직 바이트로 실제 형식을 판별합니다. 확장자를 바꿔 위장한 파일이나, 디코딩 결과가 어떤 파일인지 확인할 때 유용합니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '판별', inLabel: '데이터', outLabel: '판별 결과', placeholder: '16진수 바이트 또는 파일 열기' }],
        options: [IN('hex')],
        run: (s, o) => {
          const bytes = readBytes(s, o.inFmt);
          const hits = identifyMagic(bytes);
          const head = `처음 16 B: ${toHex(bytes.subarray(0, 16), false, ' ')}`;
          if (hits.length) return `${hits.map((h) => `✓ ${h.name}  (.${h.ext})${h.note ? `  — ${h.note}` : ''}`).join('\n')}\n\n${head}`;
          let text = null;
          try { text = utf8Decode(bytes, true); } catch { /* 바이너리 */ }
          if (text !== null && printableScore(text) > 0.95) return `알려진 시그니처는 없지만 UTF-8 텍스트로 보입니다.\n\n${head}`;
          return `알려진 시그니처와 일치하지 않습니다. 암호화되었거나, 압축되었거나, 헤더가 없는 데이터일 수 있습니다. "엔트로피 분석"으로 확인해 보세요.\n\n${head}`;
        },
      },
      {
        id: 'entropy', name: '엔트로피 분석', short: '암호화·압축 여부 추정',
        desc: '바이트 분포의 무작위성(섀넌 엔트로피)을 측정합니다. 8에 가까우면 암호문이나 압축 데이터, 낮으면 텍스트나 단순 인코딩일 가능성이 높습니다. 구간별 그래프로 파일 안의 암호화 영역도 찾을 수 있습니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '분석', inLabel: '데이터', outLabel: '분석 결과' }],
        options: [IN('text')],
        run: (s, o) => entropyReport(readBytes(s, o.inFmt)),
      },
      {
        id: 'strings', name: '문자열 추출', short: 'ASCII · UTF-16 strings',
        desc: '바이너리 안에 들어 있는 읽을 수 있는 문자열을 오프셋과 함께 뽑아냅니다(유닉스 strings 명령과 같음). 실행 파일에서 URL, 경로, 메시지를 찾을 때 씁니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '추출', inLabel: '데이터', outLabel: '문자열 목록' }],
        options: [
          IN('hex'),
          { id: 'min', label: '최소 길이', type: 'number', default: 4, min: 2, max: 100 },
          { id: 'enc', label: '종류', type: 'select', default: 'both', choices: [['both', 'ASCII + UTF-16LE'], ['ascii', 'ASCII'], ['utf16', 'UTF-16LE']] },
        ],
        run: (s, o) => extractStrings(readBytes(s, o.inFmt), { min: Math.max(2, Number(o.min) || 4), enc: o.enc }),
      },
      {
        id: 'xorbrute', name: 'XOR 전수 조사', short: '단일 바이트 키 자동 탐색',
        desc: '256가지 단일 바이트 키로 모두 XOR한 뒤, 영어 문장에 가까운 결과부터 보여줍니다. "포함 문자열"에 flag 같은 알려진 평문을 넣으면 후보를 좁힐 수 있습니다.',
        fileInput: true,
        modes: [{ id: 'run', label: '전수 조사', inLabel: '암호문', outLabel: '후보 (점수순)', placeholder: '16진수 바이트 (예: 1b37373331363f78…)' }],
        options: [
          IN('hex'),
          { id: 'crib', label: '포함 문자열', type: 'text', default: '' },
          { id: 'top', label: '후보 수', type: 'number', default: 10, min: 1, max: 256 },
        ],
        run: (s, o) => xorBrute(readBytes(s, o.inFmt), o),
      },
      {
        id: 'datauri', name: 'Data URI 분석', short: 'data:…;base64, 해석',
        desc: 'HTML·CSS나 피싱 메일에 숨겨진 data: URI를 풀어서 MIME 타입, 크기, 실제 파일 형식, 내용을 보여줍니다. 선언된 타입과 실제 형식이 다르면 경고합니다.',
        modes: [{ id: 'run', label: '분석', inLabel: 'Data URI', outLabel: '분석 결과', placeholder: 'data:text/html;base64,PGgxPkhpPC9oMT4=' }],
        run: (s) => parseDataUri(s),
      },
    ],
  });
})(globalThis.DecryptLab);
