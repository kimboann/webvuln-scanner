# WebVuln Scanner

현재 접속한 웹페이지의 코드를 정적 분석해서 취약점을 찾아주는 Chrome 확장 프로그램.

서버 없이 동작하고, 모든 분석은 브라우저 안에서만 이루어집니다.

---

## 탐지 항목 (26종)

**XSS**
- `innerHTML` / `outerHTML` 직접 할당
- `document.write()` 사용
- `javascript:` URI 스킴
- `postMessage` origin 미검증
- 인라인 이벤트 핸들러 (`onclick`, `onerror` 등)
- React `dangerouslySetInnerHTML` 사용
- JSONP 사용

**Code Injection**
- `eval()` / `new Function()` 사용
- `setTimeout` / `setInterval`에 문자열 전달

**Sensitive Data Exposure**
- 하드코딩된 API Key / Password / Token (AWS, Stripe 등 포함)
- `localStorage` / `sessionStorage`에 민감 정보 저장
- URL 쿼리 파라미터에 민감 정보 노출

**Cryptography**
- 취약한 암호화 알고리즘 (MD5, SHA-1, RC4, DES)
- `Math.random()` 보안 목적 사용

**Transport Security**
- 혼합 콘텐츠 (HTTPS 페이지의 HTTP 리소스)
- 암호화되지 않은 WebSocket (`ws://`)
- HTTP로 폼 데이터 전송

**Session Security**
- JS에서 접근 가능한 쿠키 (HttpOnly 미설정)

**Security Headers**
- Content Security Policy (CSP) 누락
- 클릭재킹 방어 헤더 누락 (X-Frame-Options / frame-ancestors)

**Supply Chain**
- 외부 스크립트/스타일시트 SRI(Subresource Integrity) 누락

**Iframe Security**
- `iframe` sandbox 속성 누락

**CORS**
- `Access-Control-Allow-Origin: *` 와일드카드 설정

**Prototype Pollution**
- `__proto__`, `constructor.prototype` 조작 패턴

**Open Redirect**
- 검증 없는 URL 리다이렉트

**Information Disclosure**
- `debugger` 문 잔류 / 민감 정보 `console.log`

정적 분석 기반이라 외부 JS 파일 내부나 난독화된 코드는 탐지하지 못합니다.

---

## 설치

1. `chrome://extensions/` 접속
2. 개발자 모드 ON
3. "압축해제된 확장 프로그램을 로드합니다" → 이 폴더 선택

---

## 사용법

분석할 페이지에서 확장 아이콘 클릭 → 스캔 시작 → 결과 확인

---

## 기술 스택

Chrome Extension Manifest V3 / Vanilla JS / 외부 의존성 없음
