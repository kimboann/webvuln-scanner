# WebVuln Scanner

현재 접속한 웹페이지의 코드를 정적 분석해서 취약점을 찾아주는 Chrome 확장 프로그램.

서버 없이 동작하고, 모든 분석은 브라우저 안에서만 이루어집니다.

---

## 탐지 항목

- `eval()`, `new Function()` 사용
- 하드코딩된 API Key / Password / Token
- `javascript:` URI 스킴
- `innerHTML` / `outerHTML` 직접 할당
- `document.write()` 사용
- `setTimeout` / `setInterval`에 문자열 전달
- Prototype Pollution 패턴 (`__proto__`, `constructor.prototype`)
- JS에서 접근 가능한 쿠키 (HttpOnly 미설정)
- `postMessage` origin 미검증
- 인라인 이벤트 핸들러 (`onclick`, `onerror` 등)
- 혼합 콘텐츠 (HTTPS 페이지의 HTTP 리소스)
- CSP 헤더 / 메타 태그 누락
- 검증 없는 URL 리다이렉트

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
