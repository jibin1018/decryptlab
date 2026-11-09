/* 공개키 암호·서명 › 키 교환 */
(function (DL) {
  'use strict';
  const { toHex, subtle, importKey, exportPair, webcryptoError, KEYGEN, pemOpt } = DL.kits.asymmetric;

  const KX = {
    'ecdh-p256': { gen: { name: 'ECDH', namedCurve: 'P-256' }, bits: 256 },
    'ecdh-p384': { gen: { name: 'ECDH', namedCurve: 'P-384' }, bits: 384 },
    x25519: { gen: { name: 'X25519' }, bits: 256 },
  };

  DL.addTool('asymmetric', {
    id: 'keyexchange', name: '키 교환', short: 'ECDH · X25519 공유 비밀',
    desc: '내 개인키와 상대방 공개키로 양쪽이 같은 공유 비밀을 계산합니다. 이 값은 보통 HKDF를 거쳐 대칭키로 쓰입니다. 입력 칸에 상대방 공개키를 넣으세요.',
    slow: true,
    modes: [
      { id: 'derive', label: '공유 비밀 계산', inLabel: '상대방 공개키', outLabel: '공유 비밀', placeholder: '-----BEGIN PUBLIC KEY----- …' },
      KEYGEN,
    ],
    options: [
      { id: 'alg', label: '알고리즘', type: 'select', default: 'x25519', choices: [['x25519', 'X25519'], ['ecdh-p256', 'ECDH P-256'], ['ecdh-p384', 'ECDH P-384']] },
      { ...pemOpt('priv', '내 개인키'), mode: 'derive' },
    ],
    keygen: async (_, o) => {
      try { return await exportPair(await subtle().generateKey(KX[o.alg].gen, true, ['deriveBits'])); } catch (e) { throw webcryptoError(e); }
    },
    derive: async (s, o) => {
      const a = KX[o.alg];
      const peer = await importKey(s, a.gen, [], 'public');
      const mine = await importKey(o.priv, a.gen, ['deriveBits'], 'private');
      try { return toHex(new Uint8Array(await subtle().deriveBits({ name: a.gen.name, public: peer }, mine, a.bits))); }
      catch (e) { throw webcryptoError(e); }
    },
  });
})(globalThis.DecryptLab);
