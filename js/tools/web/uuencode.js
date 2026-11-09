/* 웹·문자 인코딩 › UUEncode */
(function (DL) {
  'use strict';
  const { readBytes, asText } = DL.kits.web;

  const uuChar = (v) => (v === 0 ? '`' : String.fromCharCode(v + 32));
  function uuEncode(bytes, name = 'data.bin') {
    const lines = [`begin 644 ${name}`];
    for (let i = 0; i < bytes.length; i += 45) {
      const chunk = bytes.subarray(i, i + 45);
      let line = uuChar(chunk.length);
      for (let j = 0; j < chunk.length; j += 3) {
        const a = chunk[j], b = chunk[j + 1] || 0, c = chunk[j + 2] || 0;
        line += uuChar(a >> 2) + uuChar(((a << 4) | (b >> 4)) & 63) + uuChar(((b << 2) | (c >> 6)) & 63) + uuChar(c & 63);
      }
      lines.push(line);
    }
    lines.push('`', 'end');
    return lines.join('\n');
  }
  function uuDecode(s) {
    const out = [];
    const lines = s.split(/\r?\n/);
    let started = !lines.some((l) => /^begin\s/.test(l));
    for (const line of lines) {
      if (!started) { if (/^begin\s/.test(line)) started = true; continue; }
      if (/^end\s*$/.test(line)) break;
      if (!line) continue;
      const n = (line.charCodeAt(0) - 32) & 63;
      if (!n) continue;
      const vals = Array.from(line.slice(1), (c) => (c.charCodeAt(0) - 32) & 63);
      const bytes = [];
      for (let j = 0; j + 3 < vals.length + 3 && bytes.length < n; j += 4) {
        const [a, b, c, d] = [vals[j] || 0, vals[j + 1] || 0, vals[j + 2] || 0, vals[j + 3] || 0];
        bytes.push(((a << 2) | (b >> 4)) & 255, ((b << 4) | (c >> 2)) & 255, ((c << 6) | d) & 255);
      }
      out.push(...bytes.slice(0, n));
    }
    return new Uint8Array(out);
  }
  Object.assign(DL.fn, { uuEncode, uuDecode });

  DL.addTool('web', {
    id: 'uuencode', name: 'UUEncode', short: 'begin 644 … end',
    desc: '유닉스 시절부터 쓰인 바이너리→텍스트 인코딩입니다. 오래된 메일 첨부나 일부 악성코드 페이로드에서 볼 수 있습니다.',
    fileInput: true,
    options: [{ id: 'name', label: '파일 이름', type: 'text', default: 'data.bin', mode: 'encode' }],
    encode: (s, o) => uuEncode(readBytes(s, 'text'), o.name || 'data.bin'),
    decode: (s) => uuDecode(asText(s)),
  });
})(globalThis.DecryptLab);
