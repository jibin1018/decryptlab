/* 고전 암호 › Bacon 암호 */
(function (DL) {
  'use strict';
  const { A, lettersOnly, ENC_DEC } = DL.kits.classic;

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

  DL.addTool('classic', {
    id: 'bacon', name: 'Bacon 암호', short: 'A/B 5비트 · 대소문자 은닉',
    desc: '글자를 A와 B 다섯 개의 패턴으로 바꿉니다. 디코딩 시 0/1이나, 일반 문장의 소문자(A)/대문자(B) 패턴으로 숨긴 메시지도 인식합니다.',
    modes: ENC_DEC,
    options: [{ id: 'variant', label: '알파벳', type: 'select', default: '26', choices: [['26', '26글자'], ['24', '24글자 (I=J, U=V)']] }],
    encode: (s, o) => baconEnc(s, o.variant),
    decode: (s, o) => baconDec(s, o.variant),
  });
})(globalThis.DecryptLab);
