/* 바이너리 분석 — 카테고리 셸 + 공유 헬퍼 (DL.kits.binary) */
(function (DL) {
  'use strict';
  const { utf8Decode, toHex, fromHex, readBytes, fmtOption, entropy, b64decode, printableScore, latin1 } = DL;

  /* ---------- 파일 시그니처 (magic 도구 + Data URI가 공유) ---------- */
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

  /* ---------- 헥스 뷰 (hexview 도구 + Data URI가 공유) ---------- */
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
  Object.assign(DL.fn, { identifyMagic, hexdump });

  const IN = (def) => fmtOption('inFmt', '입력 형식', def, ['text', 'hex', 'base64']);

  DL.kits.binary = { utf8Decode, toHex, fromHex, readBytes, fmtOption, entropy, b64decode, printableScore, latin1, asciiChar, identifyMagic, hexdump, IN };

  DL.addCategory({
    id: 'binary',
    name: '바이너리 분석',
    desc: '헥스·파일 시그니처·엔트로피·문자열 추출',
    color: 'cyan',
    tools: [],
  });
})(globalThis.DecryptLab);
