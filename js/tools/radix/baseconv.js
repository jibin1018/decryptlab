/* 진법·데이터 표현 › 진법 변환기 */
(function (DL) {
  'use strict';
  const { parseBig, bigToRadix } = DL.kits.radix;
  const BASES = [['2', '2진수'], ['8', '8진수'], ['10', '10진수'], ['16', '16진수'], ['36', '36진수'], ['62', '62진수']];

  DL.addTool('radix', {
    id: 'baseconv', name: '진법 변환기', short: '정수 2·8·10·16·36·62진수',
    desc: '큰 정수도 정확하게(BigInt) 진법 사이를 변환합니다. 한 줄에 하나씩 여러 값을 넣을 수 있습니다.',
    modes: [{ id: 'run', label: '변환', inLabel: '숫자', placeholder: '변환할 정수 (예: 255, 0xff)' }],
    options: [{ id: 'from', label: '입력 진법', type: 'select', default: '10', choices: BASES }],
    run: (s, o) => s.split(/\r?\n/).filter((l) => l.trim()).map((line) => {
      const n = parseBig(line, Number(o.from));
      return BASES.map(([r, l]) => `${l.padEnd(5)} ${bigToRadix(n, Number(r))}`).join('\n');
    }).join('\n\n'),
  });
})(globalThis.DecryptLab);
