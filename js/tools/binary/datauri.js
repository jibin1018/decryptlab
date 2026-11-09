/* 바이너리 분석 › Data URI 분석 */
(function (DL) {
  'use strict';
  const { utf8Decode, b64decode, printableScore, identifyMagic, hexdump } = DL.kits.binary;

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

  DL.addTool('binary', {
    id: 'datauri', name: 'Data URI 분석', short: 'data:…;base64, 해석',
    desc: 'HTML·CSS나 피싱 메일에 숨겨진 data: URI를 풀어서 MIME 타입, 크기, 실제 파일 형식, 내용을 보여줍니다. 선언된 타입과 실제 형식이 다르면 경고합니다.',
    modes: [{ id: 'run', label: '분석', inLabel: 'Data URI', outLabel: '분석 결과', placeholder: 'data:text/html;base64,PGgxPkhpPC9oMT4=' }],
    run: (s) => parseDataUri(s),
  });
})(globalThis.DecryptLab);
