# WebVuln Scanner

현재 접속한 웹페이지의 코드를 정적 분석하여 주요 보안 취약점을 탐지하는 Chrome 확장 프로그램.

서버 없이 동작하며, 모든 분석은 사용자의 브라우저 로컬 안에서만 안전하게 이루어집니다.

---

## 📋 주요정보통신기반시설 기술적 취약점 평가기준 매핑 (Web Application 보안)

본 도구는 KISA의 **주요정보통신기반시설 기술적 취약점 분석·평가방법 상세가이드 (Web Application 보안 부문)**의 18대 항목들과 매핑되어 있습니다.

| 번호 | KISA 공식 취약점 구분 | 매핑 탐지 규칙 |
| :---: | :--- | :--- |
| **1** | 코드 인젝션 (Code Injection) | `JS_EVAL`, `JS_SETTIMEOUT_STRING`, `JS_PROTO_POLLUTION` |
| **4** | 에러 페이지 적용 미흡 | `DEBUG_CODE` (디버그 에러 스택 트레이스 노출 방지) |
| **5** | 정보 누출 (Information Disclosure) | `JS_HARDCODED_SECRET` (자격 증명 노출), `SENSITIVE_COMMENT` (주석 내 키 노출), `INFO_DISCLOSURE_COMMENT` (내부 경로/SQL 노출) |
| **6** | 크로스사이트 스크립팅 (XSS) | `JS_INNER_HTML`, `JS_DOM_SOURCE_TO_SINK`, `JS_DOCUMENT_WRITE`, `JS_JAVASCRIPT_URI`, `DOM_JAVASCRIPT_HREF`, `DOM_INLINE_EVENT`, `REACT_DANGEROUS_HTML`, `JSONP_USAGE`, `TEMPLATE_INJECTION`, `JS_OPEN_REDIRECT` |
| **11** | 불충분한 권한 검증 | `SENSITIVE_STORAGE` (로컬 스토리지 내 중요 세션/권한 데이터 적재) |
| **12** | 취약한 비밀번호 복구 절차 | `INSECURE_RANDOM` (보안 난수 생성 시 `Math.random()` 오용) |
| **13** | 프로세스 검증 누락 | `CORS_WILDCARD` (CORS 무제한 와일드카드 개방) |
| **15** | 파일 다운로드 | `SENSITIVE_IN_URL` (파라미터 변조를 통한 중요 경로 유실) |
| **16** | 불충분한 세션 관리 | `COOKIE_INSECURE` (HttpOnly 누락), `COOKIE_JS_SET` (스크립트 쿠키 생성) |
| **17** | 데이터 평문 전송 | `MIXED_CONTENT`, `WEBSOCKET_INSECURE`, `FORM_HTTP_ACTION` |
| **18** | 쿠키 변조 | `COOKIE_JS_SET` (클라이언트 단 서명되지 않은 쿠키 변조 가능성) |
| **기타** | WEB-STD (웹 보안 표준 설정) | `WEAK_CRYPTO`, `MISSING_CSP`, `CSP_UNSAFE`, `SRI_MISSING`, `IFRAME_NO_SANDBOX`, `IFRAME_OVERPERMISSIVE_SANDBOX`, `MISSING_CLICKJACKING_PROTECTION` |

---

## 🚀 설치 방법

1. Chrome 브라우저에서 **`chrome://extensions/`** 주소로 이동합니다.
2. 우측 상단의 **개발자 모드** 토글을 켭니다.
3. 좌측 상단의 **"압축해제된 확장 프로그램을 로드합니다"** 버튼을 누릅니다.
4. 이 확장 프로그램이 들어있는 루트 폴더를 선택합니다.

---

## 🎯 사용 방법

1. 점검 대상 웹페이지에 접속합니다.
2. 브라우저 우측 상단 확장 프로그램 바에서 **WebVuln Scanner** 아이콘을 클릭합니다.
3. **스캔 시작** 버튼을 누르면 동적으로 삽입된 스크립트 및 외부 JS 파일 소스 코드까지 비동기 로딩하여 실시간 정적 분석을 진행합니다.
4. 발견된 취약점 리스트를 확인하고, 상세 모달을 열어 취약 코드의 발생 라인 및 추천 조치 방안을 조회합니다.
