# WebVuln Scanner

현재 접속한 웹페이지의 **소스 코드**와 **DOM 구성**을 분석하여 XSS, 민감정보 노출, 평문 전송 등의 보안 취약점을 탐지하는 Chrome 확장 프로그램입니다.

모든 스캔 과정은 외부 서버 통신 없이 사용자의 웹 브라우저 **로컬 환경** 내에서만 안전하게 동작합니다.

---

## 주요 탐지 항목 (32종)

### 1. XSS & 스크립트 실행 제어
- `innerHTML` / `outerHTML` 할당 및 `insertAdjacentHTML` 호출
- `document.write()` 및 `document.writeln()` 오용
- `javascript:` URI 스킴 직접 사용 및 DOM 내 `href` 삽입
- `postMessage` 수신 시 origin 미검증 및 와일드카드(`*`) 송신
- 인라인 이벤트 핸들러 (`onclick`, `onerror`, `onload` 등 20여 종)
- React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`, Vue `v-html` 사용
- JSONP 호출 패턴 및 클라이언트 측 템플릿 인젝션 (AngularJS/Handlebars 등)
- 사용자 제어 가능한 DOM Source와 Sink의 직접적인 데이터 흐름 연결

### 2. 코드 주입 (Code Injection)
- `eval()` 및 `execScript()` 동적 실행
- `new Function()` 생성자 오용 및 간접 `eval` 패턴
- `setTimeout()` / `setInterval()` 내에 문자열 인수 및 변수 결합 주입

### 3. 정보 누출 및 디버그 코드
- 하드코딩된 API Key 및 자격 증명 (AWS, Google API, Stripe, GitHub PAT, JWT, MongoDB URI 등 20여 종)
- `localStorage` 및 `sessionStorage` 내 인증 토큰/세션 데이터 적재
- URL 쿼리 파라미터 및 Fragment(`#`) 내 중요정보 노출
- 소스 내 개발용 `debugger` 문 잔류 및 민감정보 출력 `console.log()`
- 소스코드 주석 내 내부 IP, 물리적 경로, SQL 쿼리 노출

### 4. 세션 & 쿠키 보안
- `HttpOnly` 속성이 누락된 브라우저 노출 쿠키 감지
- JavaScript(`document.cookie`)를 사용한 민감 쿠키 설정 행위

### 5. 전송 & 프로토콜 보호
- 혼합 콘텐츠 (HTTPS 환경 내 HTTP 리소스 로드) 감지
- 암호화되지 않은 WebSocket (`ws://`) 연결 및 HTTP EventSource 사용
- 암호화되지 않은 HTTP 프로토콜을 통한 `form` 데이터 전송

### 6. 보안 설정 및 공급망
- CORS `Access-Control-Allow-Origin: *` 와일드카드 과도 설정
- 클릭재킹 방어 헤더 누락 (`X-Frame-Options` 및 `frame-ancestors`)
- 외부 라이브러리 로드 시 SRI (`Subresource Integrity`) 누락
- `iframe` 내 `sandbox` 속성 누락 및 과도한 권한 설정 (`allow-scripts` + `allow-same-origin`)

---

## 설치 방법

1. Chrome 브라우저에서 **`chrome://extensions/`** 주소로 이동합니다.
2. 우측 상단의 **개발자 모드** 토글을 활성화합니다.
3. 좌측 상단의 **"압축해제된 확장 프로그램을 로드합니다"** 버튼을 선택합니다.
4. 확장 프로그램 소스 코드가 포함된 **루트 폴더**를 선택합니다.

---

## 사용 방법

1. 분석할 웹페이지에 접속합니다.
2. 브라우저 툴바 우측 상단에서 **WebVuln Scanner** 아이콘을 클릭합니다.
3. **스캔 시작** 버튼을 누르면 동적 스크립트 및 외부 로드 JS 소스를 수집하여 분석을 시작합니다.
4. 탐지된 취약점 카드를 클릭하여 **취약 설명**, **발생 줄 번호(Line Number)** 및 **조치 권고사항**을 확인합니다.
