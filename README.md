# DecryptLab

브라우저에서 바로 쓰는 인코딩·암호·분석 도구 모음입니다. 빌드 과정과 서버 로직이 없고, 모든 변환은 브라우저 안에서 처리되어 입력한 키와 데이터가 외부로 전송되지 않습니다. 외부 라이브러리도 사용하지 않습니다.

## 실행

```bash
python3 -m http.server 8765 --bind 127.0.0.1
# http://127.0.0.1:8765 접속
```

Web Crypto(SHA·HMAC·RSA 등)는 `localhost`나 HTTPS에서만 동작하므로 `index.html`을 파일로 직접 열기보다 위처럼 서버로 여는 것을 권장합니다.

## 카테고리

| 주제 | 도구 | 준비 중 |
|---|---|---|
| 자동 분석 | 종합 분석 리포트, 인코딩 자동 감지, 재귀 디코더, 해시 식별기 | — |
| Base 계열 인코딩 | Base64(URL-safe·MIME), Base32, Base58, Base58Check, Base62, Base36, Base45, Ascii85, Z85, basE91, Hex | — |
| 웹·문자 인코딩 | URL, HTML·XML 엔티티, 유니코드 이스케이프, JS·C 이스케이프, UTF-16/32, Punycode·IDN, MIME Encoded-Word, Quoted-Printable, UUEncode, 문자셋 해석(EUC-KR 등) | — |
| 진법·데이터 표현 | 2/8/10진수, 코드 포인트, 진법 변환기, IEEE 754, 정수·엔디안 해석, VarInt·ZigZag | — |
| 고전 암호 | 빈도 분석·키 추정, 카이사르, ROT13/47, Atbash, Affine, 단일 치환, 비즈네르, Beaufort, Autokey, Playfair, Hill, Polybius, Bifid, ADFGVX, 열 전치, 레일펜스, Bacon, XOR, 모스 | — |
| 대칭키 암호 | AES·ARIA·SEED (ECB·CBC·CTR·CFB·OFB·GCM, 5종 패딩), ChaCha20-Poly1305, OpenSSL·CryptoJS 호환, RC4 | — |
| 공개키 암호·서명 | RSA-OAEP, 전자서명(ECDSA·Ed25519·RSA-PSS·PKCS#1), 키 교환(X25519·ECDH), 교과서 RSA(CTF) | — |
| 해시·MAC·KDF | 해시(MD5·SHA-1/2·SHA-3·Keccak·BLAKE2·RIPEMD-160·SM3·CRC16/32/32C/64·Adler-32·FNV·xxHash·MurmurHash3), SHAKE, HMAC, PBKDF2·scrypt·HKDF | BLAKE3·Whirlpool, bcrypt·Argon2 |
| 압축·데이터 복원 | Gzip·Zlib·Raw DEFLATE 압축/해제, LZ4 해제, 압축 형식 식별, ZIP 목록·추출, Brotli·Zstd 해제(브라우저가 지원할 때만 표시) | LZMA·XZ·Bzip2 |
| 웹 토큰·인증서 | JWT 디코더, JWT 서명 검증·생성(HS·RS·PS·ES·EdDSA), JWT 서명키 사전 공격(HS256/384/512), JWE 복호화(dir·RSA-OAEP·AES-KW / GCM·CBC-HS), JWK↔PEM, PEM·DER·ASN.1 뷰어, X.509 인증서, SAML 디코더 | JWE ECDH-ES·PBES2 |
| 바이너리 분석 | 헥스 뷰어, 파일 시그니처 판별, 엔트로피 분석, 문자열 추출, XOR 전수 조사, Data URI 분석 | — |

## 검증

- AES·ARIA는 6개 운용 모드 전부를 Node.js(OpenSSL)와 바이트 단위로 비교했습니다. SEED는 `openssl enc -seed-cbc`와, ChaCha20-Poly1305는 Node와 비교했습니다.
- FIPS-197, RFC 8439, KISA SEED, ARIA 공식 테스트 벡터를 확인했습니다.
- 해시·HMAC·PBKDF2·HKDF·SHA-3·SHAKE·BLAKE2는 Node `crypto`와 결과를 비교했고, 여러 블록에 걸치는 경계 길이도 확인했습니다. RIPEMD-160·SM3·scrypt도 Node와 비교했고, CRC·Adler·FNV·xxHash·MurmurHash3는 표준 검사값으로 확인했습니다.
- 압축은 Node `zlib`과 `gzip`·`zip` 명령으로 만든 파일로, X.509·ASN.1은 `openssl req`로 만든 인증서와 지문으로, JWT·JWK·JWE는 Node가 만든 키·서명·암호문으로 상호 검증했습니다. LZ4는 `lz4` 명령으로 만든 파일로 확인했습니다.
- RSA·ECDSA 키와 서명은 Node가 만든 키 및 검증 결과와 상호 호환됩니다.
- 동기 SHA-256/384/512와 HMAC(서명키 사전 공격용)은 여러 길이에서 Node와 일치하며, 찾은 키는 서명 검증 도구로 교차 확인했습니다.
- 고전 암호는 위키백과 예제값으로 확인했습니다.
- 모든 도구는 모든 모드에서 이상한 입력을 넣었을 때 설명이 담긴 오류 메시지로 실패합니다.

## 구조

- `index.html`: 진입점. 스크립트 순서가 곧 카테고리 순서입니다.
- `css/style.css`: 스타일(라이트/다크 테마)
- `js/core.js`: 공통 기능(바이트 변환, 입출력 형식, PEM, ASN.1 DER, MD5·CRC32, 카테고리 레지스트리)
- `js/tools/*.js`: 카테고리별 도구 정의. 하나의 파일이 `DL.addCategory()`로 카테고리 하나를 등록합니다.
- `js/app.js`: 해시 라우팅(`#/카테고리/도구`)과 화면 렌더링

### 도구 추가하기

```js
{
  id: 'example', name: '예시', short: '목차에 표시될 짧은 설명', desc: '본문 설명',
  modes: [{ id: 'encrypt', label: '암호화' }, { id: 'decrypt', label: '복호화' }], // 생략 시 인코딩/디코딩
  options: [{ id: 'key', label: '키', type: 'text', default: '', when: (o) => true }],
  encrypt: (input, opts) => '문자열 · Uint8Array · Promise 반환',
  decrypt: (input, opts) => '…',
}
```

아직 만들지 않은 도구는 카테고리의 `planned: [['이름', '설명'], …]`에 넣으면 화면에 "준비 중"으로 표시됩니다.
