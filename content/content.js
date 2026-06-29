/**
 * content.js
 * 페이지 DOM 및 JavaScript 코드를 정적 분석하는 Content Script
 * popup.js의 요청을 받아 분석을 수행하고 결과를 반환합니다.
 */

(() => {
  'use strict';

  // ─── 취약점 탐지 규칙 ─────────────────────────────
  const VULN_RULES = {

    // ════════════════════════════════════════
    // XSS — DOM Sink
    // ════════════════════════════════════════
    JS_INNER_HTML: {
      id: 'JS_INNER_HTML',
      name: 'innerHTML / outerHTML 사용',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        // 바닐라 JS DOM sink
        /\.innerHTML\s*[\+]?=/g,
        /\.outerHTML\s*[\+]?=/g,
        /\.insertAdjacentHTML\s*\(/g,

        // jQuery HTML injection sink
        /\.\s*html\s*\(\s*[^)]+\)/g,
        /\.\s*append\s*\(\s*['"`<]/g,
        /\.\s*prepend\s*\(\s*['"`<]/g,
        /\.\s*after\s*\(\s*['"`<]/g,
        /\.\s*before\s*\(\s*['"`<]/g,
        /\.\s*replaceWith\s*\(\s*['"`<]/g,
        /\.\s*wrapAll\s*\(\s*['"`<]/g,
        /\.\s*wrapInner\s*\(\s*['"`<]/g,
        /\$\s*\(\s*['"`]\s*<[^>]+>/g,

        // DOM write via property
        /\.srcdoc\s*=/g,
      ],
      description: '사용자 입력이 innerHTML, jQuery .html() 등 DOM sink에 직접 삽입되면 XSS 공격에 취약합니다.',
      recommendation: 'textContent / createElement 또는 DOMPurify로 새니타이즈 후 삽입하세요. jQuery는 .text()를 사용하세요.',
    },

    JS_DOM_SOURCE_TO_SINK: {
      id: 'JS_DOM_SOURCE_TO_SINK',
      name: 'DOM 소스 → 위험 함수 연결',
      severity: 'CRITICAL',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        // location.hash → innerHTML 패턴
        /location\.(?:hash|search|href).*\.innerHTML/gs,
        /location\.(?:hash|search|href).*document\.write/gs,
        /location\.(?:hash|search|href).*\.html\s*\(/gs,
        /location\.(?:hash|search|href).*eval\s*\(/gs,

        // document.referrer → sink
        /document\.referrer.*\.innerHTML/gs,
        /document\.referrer.*document\.write/gs,
        /document\.referrer.*eval\s*\(/gs,

        // URL 파라미터를 추출 → sink
        /URLSearchParams.*\.innerHTML/gs,
        /URLSearchParams.*document\.write/gs,
        /URLSearchParams.*\.html\s*\(/gs,

        // document.URL, document.documentURI → sink
        /document\.(?:URL|documentURI|baseURI).*\.innerHTML/gs,
        /document\.(?:URL|documentURI|baseURI).*document\.write/gs,

        // window.name → sink (고전적 XSS 벡터)
        /window\.name.*\.innerHTML/gs,
        /window\.name.*document\.write/gs,
        /window\.name.*eval\s*\(/gs,
      ],
      description: 'URL 파라미터, hash, referrer 등 사용자 제어 가능한 소스가 DOM sink에 직접 연결되어 있습니다. 가장 위험한 DOM XSS 패턴입니다.',
      recommendation: '사용자 입력 소스를 반드시 DOMPurify 등으로 새니타이즈한 후 DOM에 삽입하세요.',
    },

    JS_DOCUMENT_WRITE: {
      id: 'JS_DOCUMENT_WRITE',
      name: 'document.write() 사용',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        /document\.write\s*\(/g,
        /document\.writeln\s*\(/g,
        /document\.open\s*\(\s*\)/g,
      ],
      description: 'document.write()는 외부 입력값 포함 시 XSS를 유발할 수 있으며, 성능 문제도 발생합니다.',
      recommendation: 'DOM 조작 API(createElement, appendChild 등)로 대체하세요.',
    },

    JS_JAVASCRIPT_URI: {
      id: 'JS_JAVASCRIPT_URI',
      name: 'javascript: URI 스킴 사용',
      severity: 'CRITICAL',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        /["'`]javascript:/gi,
        /\.href\s*=\s*.*javascript:/gi,
        /\.src\s*=\s*.*javascript:/gi,
        /\.action\s*=\s*.*javascript:/gi,
      ],
      description: 'javascript: URI는 XSS 공격에 직접 악용될 수 있습니다.',
      recommendation: 'javascript: URI를 제거하고 이벤트 핸들러를 사용하세요.',
    },

    DOM_JAVASCRIPT_HREF: {
      id: 'DOM_JAVASCRIPT_HREF',
      name: 'DOM에서 javascript: href 사용',
      severity: 'CRITICAL',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'dom_selector',
      selectors: [
        'a[href^="javascript:"]',
        'a[href^="JavaScript:"]',
        'a[href^="JAVASCRIPT:"]',
        'iframe[src^="javascript:"]',
        'form[action^="javascript:"]',
        'object[data^="javascript:"]',
        'embed[src^="javascript:"]',
      ],
      description: 'HTML 요소의 href/src에 javascript: 스킴이 직접 사용되어 XSS를 유발합니다.',
      recommendation: 'javascript: URI를 완전히 제거하세요.',
    },

    JS_POSTMESSAGE_UNSAFE: {
      id: 'JS_POSTMESSAGE_UNSAFE',
      name: '안전하지 않은 postMessage 사용',
      severity: 'HIGH',
      cwe: 'CWE-346',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        // 수신: origin 검증 없이 message 리스너 등록
        /addEventListener\s*\(\s*["']message["']/g,
        /onmessage\s*=/g,

        // 발신: 와일드카드 origin으로 postMessage 전송
        /\.postMessage\s*\([^)]+,\s*["']\*["']\s*\)/g,
      ],
      description: 'postMessage 핸들러에서 origin 검증 없이 메시지를 수신하거나, 와일드카드(*)로 전송하면 악성 메시지 주입이 가능합니다.',
      recommendation: 'event.origin을 반드시 검증하고, 발신 시 정확한 origin을 지정하세요.',
    },

    DOM_INLINE_EVENT: {
      id: 'DOM_INLINE_EVENT',
      name: '인라인 이벤트 핸들러 사용',
      severity: 'MEDIUM',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'dom_selector',
      selectors: [
        '[onclick]','[onerror]','[onload]','[onmouseover]','[onmouseout]',
        '[onfocus]','[onblur]','[onkeydown]','[onkeyup]','[onsubmit]',
        '[onchange]','[ondblclick]','[oncontextmenu]','[oninput]',
        '[onpaste]','[ondrag]','[ondrop]','[onscroll]','[onwheel]',
        '[onanimationend]','[ontransitionend]','[onresize]',
        '[ontouchstart]','[ontouchmove]','[onbeforeunload]',
      ],
      description: '인라인 이벤트 핸들러는 XSS 공격 표면을 넓히며 CSP strict-dynamic 정책과 충돌합니다.',
      recommendation: 'addEventListener()를 사용하고 CSP에 unsafe-inline을 제거하세요.',
    },

    REACT_DANGEROUS_HTML: {
      id: 'REACT_DANGEROUS_HTML',
      name: 'React/프레임워크 안전하지 않은 HTML 렌더링',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        // React
        /dangerouslySetInnerHTML/g,

        // Angular
        /\[innerHTML\]\s*=/g,
        /bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)/g,
        /DomSanitizer/g,

        // Vue
        /v-html\s*=/g,
      ],
      description: 'React dangerouslySetInnerHTML, Angular bypassSecurityTrust, Vue v-html은 프레임워크의 XSS 방어를 명시적으로 우회합니다.',
      recommendation: '사용자 입력 렌더링 시 반드시 DOMPurify 등으로 새니타이즈하세요.',
    },

    JSONP_USAGE: {
      id: 'JSONP_USAGE',
      name: 'JSONP 사용',
      severity: 'MEDIUM',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        /[?&]callback\s*=/gi,
        /[?&]jsonp\s*=/gi,
        /[?&]cb\s*=/gi,
        /[?&]jsonpcallback\s*=/gi,
        /\.src\s*=.*[?&]callback=/gi,
        /createElement\s*\(\s*["']script["']\s*\)[\s\S]{0,200}callback/gi,
      ],
      description: 'JSONP는 임의의 JavaScript를 실행할 수 있어 XSS 및 데이터 탈취에 취약합니다.',
      recommendation: 'JSONP 대신 CORS를 지원하는 JSON API를 사용하세요.',
    },

    TEMPLATE_INJECTION: {
      id: 'TEMPLATE_INJECTION',
      name: '클라이언트 측 템플릿 인젝션',
      severity: 'HIGH',
      cwe: 'CWE-94',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [
        // 동적 템플릿 문자열이 사용자 입력으로 구성
        /\$\{.*location\.(?:hash|search|href)/g,
        /\$\{.*document\.(?:referrer|URL|cookie)/g,

        // Mustache/Handlebars triple-stache (unescaped)
        /\{\{\{[^}]+\}\}\}/g,

        // AngularJS expression injection
        /\$scope\.\$eval\s*\(/g,
        /\$parse\s*\(/g,
        /\$compile\s*\(/g,
      ],
      description: '사용자 입력이 템플릿 표현식에 삽입되면 클라이언트 측 코드 실행이 가능합니다.',
      recommendation: '사용자 입력을 템플릿 컨텍스트에 삽입하지 말고, 자동 이스케이프를 활성화하세요.',
    },

    // ════════════════════════════════════════
    // Code Injection
    // ════════════════════════════════════════
    JS_EVAL: {
      id: 'JS_EVAL',
      name: 'eval() / 동적 코드 실행',
      severity: 'CRITICAL',
      cwe: 'CWE-95',
      category: 'Code Injection',
      type: 'js_pattern',
      patterns: [
        // 직접적인 eval
        /\beval\s*\(/g,
        /\bexecScript\s*\(/g,

        // new Function으로 코드 생성
        /new\s+Function\s*\(/g,

        // 간접 eval 패턴
        /\bwindow\s*\[\s*["'`]eval["'`]\s*\]/g,
        /\bglobalThis\s*\[\s*["'`]eval["'`]\s*\]/g,
        /\bthis\s*\[\s*["'`]eval["'`]\s*\]/g,

        // (0, eval) 간접 호출
        /\(\s*0\s*,\s*eval\s*\)/g,

        // import()에 사용자 입력
        /\bimport\s*\(.*location\./g,
        /\bimport\s*\(.*document\.\w/g,
      ],
      description: 'eval(), new Function(), 간접 eval, 동적 import 등은 임의의 코드를 실행하므로 코드 인젝션 위험이 있습니다.',
      recommendation: 'eval() 사용을 금지하세요. JSON 파싱은 JSON.parse(), 동적 모듈은 정적 import를 사용하세요.',
    },

    JS_SETTIMEOUT_STRING: {
      id: 'JS_SETTIMEOUT_STRING',
      name: 'setTimeout/setInterval에 문자열 인수 사용',
      severity: 'HIGH',
      cwe: 'CWE-95',
      category: 'Code Injection',
      type: 'js_pattern',
      patterns: [
        /setTimeout\s*\(\s*["'`]/g,
        /setInterval\s*\(\s*["'`]/g,
        /setTimeout\s*\(\s*\w+\s*\+/g,
        /setInterval\s*\(\s*\w+\s*\+/g,
      ],
      description: 'setTimeout/setInterval에 문자열을 전달하면 eval()과 동일한 위험이 발생합니다. 변수 연결도 위험합니다.',
      recommendation: '문자열 대신 함수 참조를 사용하세요: setTimeout(() => { ... }, delay)',
    },

    // ════════════════════════════════════════
    // Sensitive Data Exposure
    // ════════════════════════════════════════
    JS_HARDCODED_SECRET: {
      id: 'JS_HARDCODED_SECRET',
      name: '하드코딩된 민감 정보',
      severity: 'CRITICAL',
      cwe: 'CWE-798',
      category: 'Sensitive Data Exposure',
      type: 'js_pattern',
      patterns: [
        // 일반 키/비밀번호/토큰
        /(?:api[_-]?key|apikey)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}/gi,
        /(?:secret[_-]?key|secret)\s*[:=]\s*["'`][^"'`\s]{8,}/gi,
        /(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`\s]{6,}/gi,
        /(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["'`][A-Za-z0-9_\-\.]{16,}/gi,
        /(?:private[_-]?key)\s*[:=]\s*["'`][^"'`\s]{16,}/gi,

        // AWS
        /AKIA[0-9A-Z]{16}/g,
        /AWS_(?:SECRET|ACCESS)[_A-Z]*\s*[:=]\s*["'`][A-Za-z0-9\/\+]{20,}/g,

        // Google
        /AIza[0-9A-Za-z_\-]{35}/g,

        // Firebase
        /(?:firebase|firebaseio)\.com[^"'`\s]{10,}/g,

        // Slack
        /xox[bpors]-[0-9]{10,}-[0-9a-zA-Z]{10,}/g,

        // GitHub
        /gh[pousr]_[A-Za-z0-9_]{36}/g,
        /github_pat_[A-Za-z0-9_]{22,}/g,

        // Stripe
        /(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}/g,

        // Twilio
        /SK[0-9a-fA-F]{32}/g,

        // SendGrid
        /SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}/g,

        // JWT (eyJ로 시작하는 토큰)
        /["'`]eyJ[A-Za-z0-9_\-]{30,}\.eyJ[A-Za-z0-9_\-]{30,}\.[A-Za-z0-9_\-]{30,}["'`]/g,

        // PEM private key
        /-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP|DSA)\s+PRIVATE\s+KEY/g,

        // MongoDB connection string
        /mongodb(?:\+srv)?:\/\/[^"'`\s]{10,}/g,

        // Redis
        /redis:\/\/[^"'`\s]*:[^@"'`\s]+@/g,

        // Generic connection string with password
        /(?:mysql|postgres|postgresql|mssql):\/\/[^:]+:[^@"'`\s]+@/g,

        // Mailgun
        /key-[0-9a-zA-Z]{32}/g,

        // Heroku
        /heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
      ],
      description: 'API 키, 패스워드, 토큰, 연결 문자열 등 민감 정보가 소스 코드에 하드코딩되어 있습니다.',
      recommendation: '환경 변수나 비밀 관리 서비스(Vault, AWS Secrets Manager 등)를 사용하고 소스 코드에서 제거하세요.',
    },

    SENSITIVE_STORAGE: {
      id: 'SENSITIVE_STORAGE',
      name: 'localStorage/sessionStorage에 민감 정보 저장',
      severity: 'HIGH',
      cwe: 'CWE-922',
      category: 'Sensitive Data Exposure',
      type: 'js_pattern',
      patterns: [
        /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`][^"'`]*(?:token|password|passwd|secret|key|auth|credential|jwt|session|bearer)[^"'`]*["'`]/gi,
        /(?:localStorage|sessionStorage)\s*\[["'`][^"'`]*(?:token|password|secret|key|auth|jwt|session)[^"'`]*["'`]\]\s*=/gi,
        /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`]user["'`]/gi,
      ],
      description: 'localStorage/sessionStorage는 XSS 공격 시 쉽게 탈취됩니다. 민감 정보를 저장하면 인증 우회가 가능합니다.',
      recommendation: '인증 토큰은 HttpOnly 쿠키에 저장하고, 민감 정보는 클라이언트에 보관하지 마세요.',
    },

    SENSITIVE_IN_URL: {
      id: 'SENSITIVE_IN_URL',
      name: 'URL 쿼리 파라미터에 민감 정보 노출',
      severity: 'HIGH',
      cwe: 'CWE-598',
      category: 'Sensitive Data Exposure',
      type: 'url_check',
      description: 'URL 파라미터에 포함된 민감 정보는 서버 로그, 브라우저 히스토리, Referer 헤더에 노출됩니다.',
      recommendation: '민감 정보는 POST 본문 또는 Authorization 헤더로 전달하세요.',
    },

    SENSITIVE_COMMENT: {
      id: 'SENSITIVE_COMMENT',
      name: 'HTML 주석에 민감 정보 노출',
      severity: 'MEDIUM',
      cwe: 'CWE-615',
      category: 'Sensitive Data Exposure',
      type: 'html_comment',
      description: 'HTML 주석에 서버 경로, 데이터베이스 정보, TODO, 비밀번호 등이 포함되어 있습니다.',
      recommendation: 'HTML 주석에 민감한 내부 정보를 포함하지 마세요. 배포 시 불필요한 주석을 제거하세요.',
    },

    // ════════════════════════════════════════
    // Prototype Pollution
    // ════════════════════════════════════════
    JS_PROTO_POLLUTION: {
      id: 'JS_PROTO_POLLUTION',
      name: 'Prototype Pollution 가능성',
      severity: 'HIGH',
      cwe: 'CWE-1321',
      category: 'Prototype Pollution',
      type: 'js_pattern',
      patterns: [
        /\.__proto__\s*[=\[]/g,
        /\[["']__proto__["']\]/g,
        /constructor\s*\[\s*["']prototype["']\]/g,
        /constructor\.prototype/g,
        /Object\.prototype\[/g,

        // 동적 키로 재귀적 병합 (깊은 복사에서 자주 발생)
        /Object\.assign\s*\(\s*\{\s*\}\s*,.*(?:req\.body|req\.query|req\.params|input|data|payload)/gi,

        // lodash/underscore merge/set 패턴 (프론트엔드에서도 사용)
        /(?:_|lodash)\.(?:merge|defaultsDeep|set|setWith)\s*\(/g,
      ],
      description: '객체의 __proto__나 constructor.prototype을 수정하면 전체 객체가 오염됩니다. merge/assign 시 입력 키 검증이 없으면 위험합니다.',
      recommendation: 'Object.create(null)로 프로토타입 없는 객체를 사용하고, 입력 키에서 __proto__, constructor, prototype을 필터링하세요.',
    },

    // ════════════════════════════════════════
    // Open Redirect (소스 연결 패턴 위주)
    // ════════════════════════════════════════
    JS_OPEN_REDIRECT: {
      id: 'JS_OPEN_REDIRECT',
      name: '검증 없는 URL 리다이렉트',
      severity: 'MEDIUM',
      cwe: 'CWE-601',
      category: 'Open Redirect',
      type: 'js_pattern',
      patterns: [
        // 사용자 입력 소스 → 리다이렉트 (정밀 패턴)
        /location\s*(?:\.href)?\s*=\s*(?:.*(?:location\.(?:hash|search)|URLSearchParams|document\.referrer|getParameter|params|query))/gi,
        /location\.replace\s*\(\s*(?:.*(?:location\.(?:hash|search)|URLSearchParams|document\.referrer|getParameter|params|query))/gi,
        /location\.assign\s*\(\s*(?:.*(?:location\.(?:hash|search)|URLSearchParams|document\.referrer|getParameter|params|query))/gi,
        /window\.open\s*\(\s*(?:.*(?:location\.(?:hash|search)|URLSearchParams|document\.referrer|getParameter|params|query))/gi,

        // redirect, return_url, next 등 쿼리 파라미터 기반
        /[?&](?:redirect|return|returnUrl|return_url|next|url|goto|target|dest|destination|continue|redir)\s*=/gi,
      ],
      description: '사용자 입력(URL 파라미터, referrer 등)이 검증 없이 리다이렉트에 사용되면 피싱 공격에 악용됩니다.',
      recommendation: '리다이렉트 전 허용 도메인 화이트리스트를 검증하세요. 상대 경로만 허용하는 것도 방법입니다.',
    },

    // ════════════════════════════════════════
    // Weak Cryptography
    // ════════════════════════════════════════
    WEAK_CRYPTO: {
      id: 'WEAK_CRYPTO',
      name: '취약한 암호화 알고리즘 사용',
      severity: 'HIGH',
      cwe: 'CWE-327',
      category: 'Cryptography',
      type: 'js_pattern',
      patterns: [
        // MD5
        /\bMD5\s*\(/gi,
        /CryptoJS\.MD5/g,
        /forge\.md\.md5/g,
        /SparkMD5/g,
        /md5\s*\.\s*(?:hex|digest|update|create)/gi,

        // SHA-1
        /CryptoJS\.SHA1\b/g,
        /forge\.md\.sha1/g,
        /\bsha1\s*\(/gi,
        /sha1\s*\.\s*(?:hex|digest|update|create)/gi,

        // RC4 / DES
        /CryptoJS\.(?:RC4|DES|TripleDES|Rabbit)\b/g,
        /forge\.cipher\.(?:createCipher|createDecipher)\s*\(\s*["'](?:DES|3DES|RC4)/gi,

        // createHash에 약한 알고리즘
        /createHash\s*\(\s*["'`](?:md5|sha1|md4|ripemd|ripemd160)["'`]\)/gi,

        // SubtleCrypto with weak algo
        /subtle\.(?:digest|importKey|sign|verify)\s*\(\s*(?:\{[^}]*name\s*:\s*)?["'](?:SHA-1)["']/gi,

        // 문자열 리터럴로 알고리즘 지정
        /["'`](?:md5|sha-?1|rc4|des|3des|des-ede|blowfish)["'`]/gi,
      ],
      description: 'MD5, SHA-1, RC4, DES, Blowfish는 충돌/브루트포스 공격에 취약한 구식 알고리즘입니다.',
      recommendation: 'SHA-256 이상(SHA-3, bcrypt, Argon2)을 사용하세요. 브라우저에서는 Web Crypto API(SubtleCrypto)를 권장합니다.',
    },

    INSECURE_RANDOM: {
      id: 'INSECURE_RANDOM',
      name: 'Math.random() 보안 목적 사용',
      severity: 'MEDIUM',
      cwe: 'CWE-338',
      category: 'Cryptography',
      type: 'js_pattern',
      patterns: [
        // Math.random으로 토큰/키/세션 생성
        /Math\.random\s*\(\s*\).*(?:token|secret|key|session|nonce|salt|csrf|otp|uuid|uid|hash)/gi,
        /(?:token|secret|key|session|nonce|salt|csrf|otp|uuid|uid)\s*[:=].*Math\.random/gi,

        // Math.random().toString(36) 패턴 (고유 ID 생성에 흔히 사용)
        /Math\.random\s*\(\s*\)\.toString\s*\(\s*36\s*\)/g,

        // Math.random으로 IV/Salt 생성
        /(?:iv|salt|seed)\s*[:=].*Math\.random/gi,
      ],
      description: 'Math.random()은 암호학적으로 안전하지 않아 예측 가능한 값을 생성합니다. 보안 목적 사용은 위험합니다.',
      recommendation: 'crypto.getRandomValues(), crypto.randomUUID(), 또는 서버 사이드 CSPRNG를 사용하세요.',
    },

    // ════════════════════════════════════════
    // Transport Security
    // ════════════════════════════════════════
    MIXED_CONTENT: {
      id: 'MIXED_CONTENT',
      name: '혼합 콘텐츠 (Mixed Content)',
      severity: 'MEDIUM',
      cwe: 'CWE-311',
      category: 'Transport Security',
      type: 'dom_selector',
      httpsOnly: true,
      selectors: [
        'img[src^="http://"]',
        'script[src^="http://"]',
        'link[href^="http://"]',
        'iframe[src^="http://"]',
        'form[action^="http://"]',
        'video[src^="http://"]',
        'audio[src^="http://"]',
        'source[src^="http://"]',
        'embed[src^="http://"]',
        'object[data^="http://"]',
      ],
      description: 'HTTPS 페이지에서 HTTP 리소스를 로드하면 중간자 공격(MITM)에 취약해집니다.',
      recommendation: '모든 리소스 URL을 HTTPS로 업데이트하거나 프로토콜 상대 URL(//)을 사용하세요.',
    },

    WEBSOCKET_INSECURE: {
      id: 'WEBSOCKET_INSECURE',
      name: '암호화되지 않은 WebSocket (ws://)',
      severity: 'HIGH',
      cwe: 'CWE-311',
      category: 'Transport Security',
      type: 'js_pattern',
      patterns: [
        /new\s+WebSocket\s*\(\s*["'`]ws:\/\//g,
        /new\s+WebSocket\s*\(\s*(?!["'`]wss:)["'`]ws:/g,
        /\.connect\s*\(\s*["'`]ws:\/\//g,
        /["'`]ws:\/\/[^"'`\s]+["'`]/g,

        // EventSource(SSE) via HTTP
        /new\s+EventSource\s*\(\s*["'`]http:\/\//g,
      ],
      description: 'ws:// WebSocket 및 HTTP EventSource는 암호화되지 않아 네트워크에서 데이터가 도청당할 수 있습니다.',
      recommendation: 'wss:// (WebSocket Secure)와 HTTPS EventSource를 사용하세요.',
    },

    FORM_HTTP_ACTION: {
      id: 'FORM_HTTP_ACTION',
      name: 'HTTP로 폼 데이터 전송',
      severity: 'HIGH',
      cwe: 'CWE-319',
      category: 'Transport Security',
      type: 'form_check',
      description: 'HTTP 폼 전송은 평문으로 데이터가 전달되어 중간자 공격으로 탈취될 수 있습니다. 비밀번호 입력 필드가 포함된 경우 특히 위험합니다.',
      recommendation: '폼 action URL을 HTTPS로 변경하세요.',
    },

    // ════════════════════════════════════════
    // Session Security
    // ════════════════════════════════════════
    COOKIE_INSECURE: {
      id: 'COOKIE_INSECURE',
      name: '안전하지 않은 쿠키 설정 (HttpOnly 미설정)',
      severity: 'HIGH',
      cwe: 'CWE-614',
      category: 'Session Security',
      type: 'cookie',
      description: 'JS에서 접근 가능한 쿠키는 HttpOnly 속성이 없어, XSS 공격으로 세션이 탈취될 수 있습니다.',
      recommendation: '쿠키 설정 시 Secure, HttpOnly, SameSite=Strict 속성을 반드시 추가하세요.',
    },

    COOKIE_JS_SET: {
      id: 'COOKIE_JS_SET',
      name: 'JavaScript로 민감 쿠키 설정',
      severity: 'HIGH',
      cwe: 'CWE-614',
      category: 'Session Security',
      type: 'js_pattern',
      patterns: [
        /document\.cookie\s*=\s*["'`](?!.*(?:secure|httponly|samesite))[^"'`]*(?:token|session|auth|jwt|sid|credential)/gi,
        /document\.cookie\s*=\s*.*(?:token|session|auth|jwt|sid)\s*[=]/gi,
      ],
      description: 'JavaScript로 설정된 쿠키는 HttpOnly가 될 수 없어 XSS에 항상 노출됩니다. 특히 인증 관련 쿠키는 위험합니다.',
      recommendation: '인증 관련 쿠키는 서버 측에서 Set-Cookie 헤더로 HttpOnly; Secure; SameSite=Strict와 함께 설정하세요.',
    },

    // ════════════════════════════════════════
    // Security Headers
    // ════════════════════════════════════════
    MISSING_CSP: {
      id: 'MISSING_CSP',
      name: 'Content Security Policy (CSP) 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-693',
      category: 'Security Headers',
      type: 'meta_check',
      metaTarget: 'csp',
      description: 'CSP 헤더/메타 태그가 없으면 XSS 및 데이터 인젝션 공격 방어가 불가능합니다.',
      recommendation: '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">를 추가하세요.',
    },

    CSP_UNSAFE: {
      id: 'CSP_UNSAFE',
      name: 'CSP에 unsafe-inline / unsafe-eval 사용',
      severity: 'HIGH',
      cwe: 'CWE-693',
      category: 'Security Headers',
      type: 'meta_check',
      metaTarget: 'csp_unsafe',
      description: "CSP에 'unsafe-inline' 또는 'unsafe-eval'이 포함되면 XSS 방어 효과가 크게 감소합니다.",
      recommendation: "nonce 기반 CSP(script-src 'nonce-...')나 strict-dynamic을 사용하세요.",
    },

    MISSING_CLICKJACKING_PROTECTION: {
      id: 'MISSING_CLICKJACKING_PROTECTION',
      name: '클릭재킹 방어 헤더 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-1021',
      category: 'Security Headers',
      type: 'meta_check',
      metaTarget: 'xframe',
      description: 'X-Frame-Options 또는 CSP frame-ancestors 설정이 없으면 iframe에 페이지를 삽입하여 클릭재킹 공격이 가능합니다.',
      recommendation: "X-Frame-Options: DENY 헤더 또는 CSP frame-ancestors 'none'을 설정하세요.",
    },

    // ════════════════════════════════════════
    // Supply Chain / SRI
    // ════════════════════════════════════════
    SRI_MISSING: {
      id: 'SRI_MISSING',
      name: '외부 리소스 무결성 검증(SRI) 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-353',
      category: 'Supply Chain',
      type: 'sri_check',
      description: 'SRI(Subresource Integrity)가 없으면 외부 CDN이 손상되거나 교체될 때 악성 코드가 실행될 수 있습니다.',
      recommendation: 'integrity 속성과 crossorigin="anonymous"를 외부 스크립트/스타일시트에 추가하세요.',
    },

    // ════════════════════════════════════════
    // Iframe Security
    // ════════════════════════════════════════
    IFRAME_NO_SANDBOX: {
      id: 'IFRAME_NO_SANDBOX',
      name: 'iframe sandbox 속성 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-1021',
      category: 'Iframe Security',
      type: 'dom_selector',
      selectors: ['iframe[src]:not([sandbox])'],
      description: 'sandbox 속성이 없는 외부 iframe은 스크립트 실행, 폼 제출, 팝업 등을 제한 없이 허용합니다.',
      recommendation: 'iframe에 sandbox="allow-scripts allow-same-origin" 등 최소 권한만 부여하세요.',
    },

    IFRAME_OVERPERMISSIVE_SANDBOX: {
      id: 'IFRAME_OVERPERMISSIVE_SANDBOX',
      name: 'iframe sandbox 과도한 권한',
      severity: 'MEDIUM',
      cwe: 'CWE-1021',
      category: 'Iframe Security',
      type: 'dom_check',
      checkType: 'iframe_sandbox',
      description: 'sandbox에 allow-scripts와 allow-same-origin이 동시에 있으면 sandbox를 무력화할 수 있습니다.',
      recommendation: 'allow-scripts와 allow-same-origin을 동시에 사용하지 마세요. 필요한 최소한의 권한만 부여하세요.',
    },

    // ════════════════════════════════════════
    // CORS
    // ════════════════════════════════════════
    CORS_WILDCARD: {
      id: 'CORS_WILDCARD',
      name: 'CORS 와일드카드(*) 설정',
      severity: 'MEDIUM',
      cwe: 'CWE-942',
      category: 'CORS',
      type: 'js_pattern',
      patterns: [
        /Access-Control-Allow-Origin["'\s:,]*\*/g,
        /res(?:ponse)?\.(?:set)?[Hh]eader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\)/g,
        /headers\s*:\s*\{[^}]*["']Access-Control-Allow-Origin["']\s*:\s*["']\*["']/g,
        /["']Access-Control-Allow-Credentials["']\s*:\s*["']true["']/g,
      ],
      description: 'Access-Control-Allow-Origin: * 설정은 모든 도메인에서 API에 접근할 수 있게 합니다. Credentials: true와 결합하면 더욱 위험합니다.',
      recommendation: '신뢰하는 특정 origin만 명시적으로 허용하세요.',
    },

    // ════════════════════════════════════════
    // Debug / Information Disclosure
    // ════════════════════════════════════════
    DEBUG_CODE: {
      id: 'DEBUG_CODE',
      name: '디버그 코드 잔류',
      severity: 'LOW',
      cwe: 'CWE-489',
      category: 'Information Disclosure',
      type: 'js_pattern',
      patterns: [
        // debugger 문
        /\bdebugger\b\s*;?/g,

        // 민감 정보가 포함된 로그
        /console\s*\.\s*log\s*\([^)]*(?:password|token|secret|key|auth|credential|cookie|session)[^)]*\)/gi,
        /console\s*\.\s*(?:warn|error|info|debug|trace)\s*\([^)]*(?:password|token|secret|credential)[^)]*\)/gi,

        // 에러 스택 트레이스 노출
        /\.stack\s*\|\|?\s*["'`].*error/gi,

        // 소스맵 주석 (배포에 남아있으면 소스 노출)
        /\/\/[#@]\s*sourceMappingURL\s*=/g,
      ],
      description: 'debugger 문, 민감 정보 로그, 소스맵 참조는 프로덕션에서 내부 구조와 보안 정보를 노출합니다.',
      recommendation: '배포 전 debugger 문, 민감 로그, 소스맵 참조를 모두 제거하세요.',
    },

    INFO_DISCLOSURE_COMMENT: {
      id: 'INFO_DISCLOSURE_COMMENT',
      name: '소스코드 내 민감 주석',
      severity: 'LOW',
      cwe: 'CWE-615',
      category: 'Information Disclosure',
      type: 'js_pattern',
      patterns: [
        // TODO/FIXME/HACK/BUG에 민감 키워드
        /\/\/\s*(?:TODO|FIXME|HACK|BUG|XXX)\s*:?\s*.*(?:password|token|secret|auth|credential|admin|root|vulnerability|exploit|bypass|backdoor)/gi,

        // SQL 쿼리 (내부 테이블 구조 노출)
        /\/[/*]\s*.*(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO|SET)\s+/gi,

        // 내부 IP/경로 노출
        /\/[/*]\s*.*(?:192\.168\.|10\.0\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[\d.]+/g,
        /\/[/*]\s*.*(?:\/etc\/|C:\\\\|\/home\/|\/var\/|\/usr\/|\/opt\/)/g,
      ],
      description: 'TODO 주석, SQL 쿼리, 내부 IP 등이 소스에 남아 있으면 공격자에게 내부 구조를 노출합니다.',
      recommendation: '배포 전 내부 정보가 포함된 주석을 제거하세요.',
    },
  };


  // ─── 유틸리티 ─────────────────────────────────
  function extractCodeSnippet(code, index, len = 80) {
    const start = Math.max(0, index - 30);
    const end = Math.min(code.length, index + len);
    let snippet = code.slice(start, end).replace(/\s+/g, ' ').trim();
    if (start > 0) snippet = '...' + snippet;
    if (end < code.length) snippet += '...';
    return snippet;
  }

  function getLineNumber(code, index) {
    return code.slice(0, index).split('\n').length;
  }

  // CDN 도메인 목록 (SRI 검사에서 같은 도메인 제외용)
  const KNOWN_CDNS = [
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
    'maxcdn.bootstrapcdn.com', 'stackpath.bootstrapcdn.com',
    'ajax.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
    'code.jquery.com', 'cdn.bootcdn.net', 'cdn.tailwindcss.com',
    'kit.fontawesome.com', 'use.fontawesome.com',
    'cdn.datatables.net', 'cdn.socket.io',
    'ga.jspm.io', 'esm.sh', 'esm.run',
  ];

  function isCDNUrl(url) {
    try {
      const u = new URL(url, location.href);
      if (u.origin === location.origin) return false; // same-origin은 SRI 불필요
      return KNOWN_CDNS.some(cdn => u.hostname === cdn || u.hostname.endsWith('.' + cdn));
    } catch { return false; }
  }

  function isExternalUrl(url) {
    try {
      const u = new URL(url, location.href);
      return u.origin !== location.origin;
    } catch { return false; }
  }


  // ─── JS 패턴 분석 ─────────────────────────────
  function analyzeJSPattern(rule, scriptSources) {
    const findings = [];
    for (const { code, source } of scriptSources) {
      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(code)) !== null) {
          findings.push({
            source,
            line: getLineNumber(code, match.index),
            snippet: extractCodeSnippet(code, match.index),
            match: match[0],
          });
          if (findings.length >= 15) break;
        }
        if (findings.length >= 15) break;
      }
      if (findings.length >= 15) break;
    }
    return findings;
  }

  // ─── DOM 셀렉터 분석 ─────────────────────────────
  function analyzeDOMSelector(rule) {
    if (rule.httpsOnly && location.protocol !== 'https:') return [];
    const findings = [];
    for (const selector of rule.selectors) {
      try {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
          if (findings.length >= 15) return;
          const tag = el.tagName.toLowerCase();
          const attr = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('action') || el.getAttribute('data') || '';
          findings.push({
            source: 'DOM',
            element: tag,
            attribute: attr,
            snippet: el.outerHTML.slice(0, 160),
          });
        });
      } catch (_) {}
    }
    return findings;
  }

  // ─── 쿠키 분석 (세션 관련 쿠키 우선) ──────────
  function analyzeCookies() {
    const cookieStr = document.cookie;
    if (!cookieStr) return [];
    const cookies = cookieStr.split(';').map(c => c.trim()).filter(Boolean);
    const sessionKeywords = ['session','sess','sid','token','auth','jwt','csrf','xsrf','login','user'];
    const findings = [];

    // 세션 관련 쿠키 먼저
    cookies.forEach(cookie => {
      const name = cookie.split('=')[0].trim().toLowerCase();
      const isSessionRelated = sessionKeywords.some(k => name.includes(k));
      if (isSessionRelated && findings.length < 8) {
        findings.push({
          source: 'Cookie',
          snippet: `🔴 세션 쿠키 "${cookie.split('=')[0].trim()}" — JS에서 접근 가능 (HttpOnly 미설정)`,
          name: cookie.split('=')[0].trim(),
          sessionRelated: true,
        });
      }
    });

    // 나머지 쿠키
    cookies.forEach(cookie => {
      const name = cookie.split('=')[0].trim();
      const nameLower = name.toLowerCase();
      const isSessionRelated = sessionKeywords.some(k => nameLower.includes(k));
      if (!isSessionRelated && findings.length < 8) {
        findings.push({
          source: 'Cookie',
          snippet: `쿠키 "${name}" — JS에서 접근 가능 (HttpOnly 미설정 의심)`,
          name,
          sessionRelated: false,
        });
      }
    });

    return findings;
  }

  // ─── URL 파라미터 민감정보 확인 ───────────────────
  function checkSensitiveInURL() {
    const sensitiveKeys = [
      'token','password','passwd','pwd','secret','key','auth',
      'api_key','apikey','access_token','private_key','credential',
      'jwt','session_id','sid','bearer','client_secret','refresh_token',
    ];
    const findings = [];
    try {
      const params = new URLSearchParams(location.search);
      for (const [key, value] of params.entries()) {
        const keyLower = key.toLowerCase();
        if (sensitiveKeys.some(s => keyLower.includes(s)) && value.length > 0) {
          findings.push({
            source: 'URL',
            snippet: `URL 쿼리 파라미터에 민감 키: ?${key}=${value.slice(0, 4)}***`,
          });
        }
      }
      const hash = location.hash;
      if (hash && hash.includes('=')) {
        const hashParams = new URLSearchParams(hash.slice(1));
        for (const [key, value] of hashParams.entries()) {
          const keyLower = key.toLowerCase();
          if (sensitiveKeys.some(s => keyLower.includes(s)) && value.length > 0) {
            findings.push({
              source: 'URL Fragment',
              snippet: `URL fragment에 민감 키: #${key}=${value.slice(0, 4)}***`,
            });
          }
        }
      }
    } catch (_) {}
    return findings;
  }

  // ─── HTML 주석 분석 ─────────────────────────────
  function analyzeHTMLComments() {
    const sensitivePatterns = [
      /password/i, /passwd/i, /secret/i, /api[_-]?key/i,
      /token/i, /credential/i, /admin/i, /root/i,
      /TODO.*(?:fix|hack|remove|temporary|temp)/i,
      /FIXME/i, /HACK/i, /BUG/i,
      /(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO)/i,
      /192\.168\.\d+\.\d+/, /10\.0\.\d+\.\d+/,
      /\/etc\/(?:passwd|shadow|hosts)/,
      /BEGIN\s+(?:RSA|EC)\s+PRIVATE/,
    ];

    const findings = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT, null, false);
    let node;
    while ((node = walker.nextNode()) && findings.length < 5) {
      const text = node.textContent.trim();
      if (text.length < 5) continue;
      for (const pattern of sensitivePatterns) {
        if (pattern.test(text)) {
          findings.push({
            source: 'HTML Comment',
            snippet: text.slice(0, 120),
          });
          break;
        }
      }
    }
    return findings;
  }

  // ─── 보안 헤더 메타 태그 확인 ─────────────────────
  function checkSecurityMeta(rule) {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');

    if (rule.metaTarget === 'csp') {
      if (cspMeta) return null;
      return [{ source: 'HTML Meta', snippet: 'Content-Security-Policy 메타 태그가 존재하지 않습니다.' }];
    }

    if (rule.metaTarget === 'csp_unsafe') {
      if (!cspMeta) return null; // CSP 자체가 없으면 MISSING_CSP에서 처리
      const content = cspMeta.getAttribute('content') || '';
      const findings = [];
      if (content.includes("'unsafe-inline'")) {
        findings.push({ source: 'CSP Meta', snippet: `CSP에 'unsafe-inline' 포함: ${content.slice(0, 100)}` });
      }
      if (content.includes("'unsafe-eval'")) {
        findings.push({ source: 'CSP Meta', snippet: `CSP에 'unsafe-eval' 포함: ${content.slice(0, 100)}` });
      }
      if (content.includes('data:')) {
        findings.push({ source: 'CSP Meta', snippet: `CSP에 'data:' URI 허용: XSS 우회 가능` });
      }
      return findings.length > 0 ? findings : null;
    }

    if (rule.metaTarget === 'xframe') {
      if (cspMeta) {
        const content = cspMeta.getAttribute('content') || '';
        if (content.includes('frame-ancestors')) return null;
      }
      try {
        if (window.top !== window.self) {
          return [{ source: 'Frame Detection', snippet: '이 페이지는 현재 iframe 안에서 실행 중이며, 클릭재킹 방어가 없습니다.' }];
        }
      } catch (_) {
        return [{ source: 'Frame Detection', snippet: '페이지가 cross-origin iframe 안에 있을 수 있습니다.' }];
      }
      return [{ source: 'HTML Meta', snippet: 'X-Frame-Options 또는 CSP frame-ancestors 설정이 감지되지 않았습니다.' }];
    }

    return null;
  }

  // ─── SRI 검사 (CDN만 대상) ──────────────────────
  function checkSRI() {
    const findings = [];

    // 외부 스크립트
    document.querySelectorAll('script[src]:not([integrity])').forEach(el => {
      const src = el.getAttribute('src') || '';
      if (isCDNUrl(src) || (isExternalUrl(src) && !src.includes('google') && !src.includes('facebook') && !src.includes('analytics'))) {
        if (findings.length < 10) {
          findings.push({
            source: 'DOM',
            element: 'script',
            attribute: src,
            snippet: el.outerHTML.slice(0, 160),
          });
        }
      }
    });

    // 외부 스타일시트
    document.querySelectorAll('link[rel="stylesheet"][href]:not([integrity])').forEach(el => {
      const href = el.getAttribute('href') || '';
      if (isCDNUrl(href) || (isExternalUrl(href) && !href.includes('google') && !href.includes('fonts'))) {
        if (findings.length < 10) {
          findings.push({
            source: 'DOM',
            element: 'link',
            attribute: href,
            snippet: el.outerHTML.slice(0, 160),
          });
        }
      }
    });

    return findings;
  }

  // ─── 폼 보안 검사 ────────────────────────────────
  function checkFormSecurity() {
    const findings = [];

    document.querySelectorAll('form').forEach(form => {
      const action = (form.getAttribute('action') || '').toLowerCase();
      const hasPasswordInput = form.querySelector('input[type="password"]');
      const hasFileInput = form.querySelector('input[type="file"]');

      // HTTP로 전송하는 폼
      if (action.startsWith('http://')) {
        findings.push({
          source: 'DOM',
          element: 'form',
          snippet: `HTTP 폼 전송: action="${action.slice(0, 80)}"${hasPasswordInput ? ' [패스워드 필드 포함!]' : ''}`,
        });
      }

      // HTTPS 페이지인데 action이 없는 폼에 패스워드 필드 (OK)
      // 하지만 autocomplete="off"가 없는 패스워드 필드
      if (hasPasswordInput) {
        const autocomplete = hasPasswordInput.getAttribute('autocomplete');
        if (!autocomplete || autocomplete === 'on') {
          // 이건 낮은 우선도이므로 여기서 처리하지 않음
        }
      }

      // 파일 업로드 폼이 HTTP
      if (hasFileInput && action.startsWith('http://')) {
        findings.push({
          source: 'DOM',
          element: 'form',
          snippet: `파일 업로드 폼이 HTTP로 전송: action="${action.slice(0, 80)}"`,
        });
      }
    });

    return findings;
  }

  // ─── iframe sandbox 과도한 권한 검사 ────────────
  function checkIframeSandbox() {
    const findings = [];
    document.querySelectorAll('iframe[sandbox]').forEach(iframe => {
      const sandbox = iframe.getAttribute('sandbox') || '';
      if (sandbox.includes('allow-scripts') && sandbox.includes('allow-same-origin')) {
        findings.push({
          source: 'DOM',
          element: 'iframe',
          snippet: `sandbox="${sandbox}" — allow-scripts + allow-same-origin 조합은 sandbox를 무력화할 수 있습니다.`,
        });
      }
    });
    return findings;
  }

  // ─── 인라인/외부 스크립트 소스 수집 ──────────────
  function collectScriptSources() {
    const sources = [];

    // 인라인 <script> 태그 (핵심 분석 대상)
    document.querySelectorAll('script:not([src])').forEach((tag, i) => {
      const code = tag.textContent || '';
      if (code.trim().length > 0) {
        sources.push({ code, source: `inline-script[${i}]` });
      }
    });

    // 외부 스크립트 URL 자체 (src 패턴 탐지)
    document.querySelectorAll('script[src]').forEach(tag => {
      const src = tag.getAttribute('src') || '';
      sources.push({ code: src, source: `external-script: ${src}` });
    });

    // 인라인 이벤트 핸들러 값 수집
    const inlineEvents = [
      'onclick','onerror','onload','onmouseover','onfocus','onsubmit',
      'onkeydown','onkeyup','onchange','oninput','onblur','ondblclick',
      'oncontextmenu','ondrag','ondrop','onpaste','onbeforeunload',
    ];
    const eventCodes = [];
    document.querySelectorAll('*').forEach(el => {
      for (const ev of inlineEvents) {
        const val = el.getAttribute(ev);
        if (val) eventCodes.push(val);
      }
    });
    if (eventCodes.length > 0) {
      sources.push({ code: eventCodes.join('\n'), source: 'inline-event-handlers' });
    }

    // meta content 수집
    document.querySelectorAll('meta[content]').forEach(meta => {
      const content = meta.getAttribute('content') || '';
      if (content.length > 0) {
        sources.push({
          code: content,
          source: `meta[${meta.getAttribute('name') || meta.getAttribute('http-equiv') || ''}]`,
        });
      }
    });

    // a[href] 값도 수집 (javascript: URI, 리다이렉트 탐지용)
    document.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href') || '';
      if (href.length > 5 && !href.startsWith('#') && !href.startsWith('/') && !href.startsWith('http')) {
        sources.push({ code: href, source: `a[href]: ${href.slice(0, 60)}` });
      }
    });

    return sources;
  }

  // ─── 메인 분석 함수 ────────────────────────────
  function runAnalysis() {
    const results = [];
    const scriptSources = collectScriptSources();
    const pageUrl = location.href;
    const pageTitle = document.title;
    const isHTTPS = location.protocol === 'https:';

    for (const [, rule] of Object.entries(VULN_RULES)) {
      let findings = [];

      switch (rule.type) {
        case 'js_pattern':
          findings = analyzeJSPattern(rule, scriptSources);
          break;
        case 'dom_selector':
          findings = analyzeDOMSelector(rule);
          break;
        case 'cookie':
          findings = analyzeCookies();
          break;
        case 'meta_check':
          findings = checkSecurityMeta(rule) || [];
          break;
        case 'url_check':
          findings = checkSensitiveInURL();
          break;
        case 'html_comment':
          findings = analyzeHTMLComments();
          break;
        case 'sri_check':
          findings = checkSRI();
          break;
        case 'form_check':
          findings = checkFormSecurity();
          break;
        case 'dom_check':
          if (rule.checkType === 'iframe_sandbox') {
            findings = checkIframeSandbox();
          }
          break;
      }

      if (findings.length > 0) {
        results.push({
          rule: {
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            cwe: rule.cwe,
            category: rule.category,
            description: rule.description,
            recommendation: rule.recommendation,
          },
          count: findings.length,
          findings: findings.slice(0, 5),
        });
      }
    }

    // 심각도 순 정렬
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    results.sort((a, b) => (severityOrder[a.rule.severity] ?? 9) - (severityOrder[b.rule.severity] ?? 9));

    return {
      pageUrl,
      pageTitle,
      isHTTPS,
      scannedAt: new Date().toISOString(),
      totalVulns: results.length,
      results,
      summary: {
        CRITICAL: results.filter(r => r.rule.severity === 'CRITICAL').length,
        HIGH:     results.filter(r => r.rule.severity === 'HIGH').length,
        MEDIUM:   results.filter(r => r.rule.severity === 'MEDIUM').length,
        LOW:      results.filter(r => r.rule.severity === 'LOW').length,
      },
    };
  }

  // ─── 메시지 리스너 ────────────────────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'START_SCAN') {
      try {
        const result = runAnalysis();
        sendResponse({ success: true, data: result });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    }
    return true;
  });

})();
