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
    // XSS
    // ════════════════════════════════════════
    JS_INNER_HTML: {
      id: 'JS_INNER_HTML',
      name: 'innerHTML / outerHTML 사용',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [/\.innerHTML\s*=/g, /\.outerHTML\s*=/g, /\.insertAdjacentHTML\s*\(/g],
      description: '사용자 입력이 innerHTML/outerHTML에 직접 삽입될 경우 XSS 공격에 취약합니다.',
      recommendation: 'textContent 또는 createElement를 사용하거나, DOMPurify로 입력값을 새니타이즈하세요.',
    },
    JS_DOCUMENT_WRITE: {
      id: 'JS_DOCUMENT_WRITE',
      name: 'document.write() 사용',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [/document\.write\s*\(/g, /document\.writeln\s*\(/g],
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
      patterns: [/["'`]javascript:/gi],
      description: 'javascript: URI는 XSS 공격에 직접 악용될 수 있습니다.',
      recommendation: 'javascript: URI를 제거하고 이벤트 핸들러를 사용하세요.',
    },
    JS_POSTMESSAGE_UNSAFE: {
      id: 'JS_POSTMESSAGE_UNSAFE',
      name: '안전하지 않은 postMessage 핸들러',
      severity: 'HIGH',
      cwe: 'CWE-346',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [/addEventListener\s*\(\s*["']message["']/g],
      description: 'postMessage 이벤트 핸들러에서 origin 검증이 없으면 악성 메시지를 수신할 수 있습니다.',
      recommendation: 'event.origin을 반드시 검증하고 신뢰하는 도메인만 허용하세요.',
    },
    DOM_INLINE_EVENT: {
      id: 'DOM_INLINE_EVENT',
      name: '인라인 이벤트 핸들러 사용',
      severity: 'MEDIUM',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'dom_selector',
      selectors: ['[onclick]','[onerror]','[onload]','[onmouseover]','[onmouseout]','[onfocus]','[onblur]','[onkeydown]','[onkeyup]','[onsubmit]','[onchange]','[ondblclick]'],
      description: '인라인 이벤트 핸들러는 XSS 공격 표면을 넓히며 CSP 정책과 충돌합니다.',
      recommendation: 'addEventListener()를 사용하고 CSP에 unsafe-inline을 제거하세요.',
    },
    REACT_DANGEROUS_HTML: {
      id: 'REACT_DANGEROUS_HTML',
      name: 'React dangerouslySetInnerHTML 사용',
      severity: 'HIGH',
      cwe: 'CWE-79',
      category: 'XSS',
      type: 'js_pattern',
      patterns: [/dangerouslySetInnerHTML/g],
      description: 'dangerouslySetInnerHTML은 React의 XSS 방어를 명시적으로 우회하는 API입니다.',
      recommendation: '사용자 입력을 렌더링할 경우 DOMPurify로 새니타이즈 후 사용하세요.',
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
        /script\.src\s*=.*callback=/gi,
        /createElement\s*\(\s*["']script["']\s*\).*callback/gi,
      ],
      description: 'JSONP는 임의의 JavaScript를 실행할 수 있어 XSS 및 데이터 탈취에 취약합니다.',
      recommendation: 'JSONP 대신 CORS를 지원하는 JSON API를 사용하세요.',
    },

    // ════════════════════════════════════════
    // Code Injection
    // ════════════════════════════════════════
    JS_EVAL: {
      id: 'JS_EVAL',
      name: 'eval() / new Function() 사용',
      severity: 'CRITICAL',
      cwe: 'CWE-95',
      category: 'Code Injection',
      type: 'js_pattern',
      patterns: [/\beval\s*\(/g, /new\s+Function\s*\(/g, /\bexecScript\s*\(/g],
      description: 'eval()은 임의의 JavaScript 코드를 실행하므로 공격자가 악성 코드를 실행할 수 있습니다.',
      recommendation: 'eval() 사용을 금지하세요. JSON 파싱에는 JSON.parse()를 사용하세요.',
    },
    JS_SETTIMEOUT_STRING: {
      id: 'JS_SETTIMEOUT_STRING',
      name: 'setTimeout/setInterval에 문자열 인수 사용',
      severity: 'HIGH',
      cwe: 'CWE-95',
      category: 'Code Injection',
      type: 'js_pattern',
      patterns: [/setTimeout\s*\(\s*["'`]/g, /setInterval\s*\(\s*["'`]/g],
      description: 'setTimeout/setInterval에 문자열을 전달하면 eval()과 동일한 위험이 발생합니다.',
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
        /(?:api[_-]?key|apikey)\s*[:=]\s*["'`][A-Za-z0-9_\-]{10,}/gi,
        /(?:secret|password|passwd|pwd)\s*[:=]\s*["'`][^"'`\s]{6,}/gi,
        /(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`][A-Za-z0-9_\-\.]{10,}/gi,
        /AWS_(?:SECRET|ACCESS)[_A-Z]*\s*[:=]\s*["'`][A-Za-z0-9\/\+]{20,}/g,
        /-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY/g,
        /(?:stripe|twilio|sendgrid|mailgun)[_-]?(?:key|secret|token)\s*[:=]\s*["'`][A-Za-z0-9_\-]{10,}/gi,
      ],
      description: 'API 키, 패스워드 등 민감 정보가 소스 코드에 하드코딩되어 있습니다.',
      recommendation: '환경 변수나 비밀 관리 서비스를 사용하고 소스 코드에서 제거하세요.',
    },
    SENSITIVE_STORAGE: {
      id: 'SENSITIVE_STORAGE',
      name: 'localStorage/sessionStorage에 민감 정보 저장',
      severity: 'HIGH',
      cwe: 'CWE-922',
      category: 'Sensitive Data Exposure',
      type: 'js_pattern',
      patterns: [
        /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`][^"'`]*(?:token|password|passwd|secret|key|auth|credential|jwt|session)[^"'`]*["'`]/gi,
        /(?:localStorage|sessionStorage)\s*\[["'`][^"'`]*(?:token|password|secret|key|auth)[^"'`]*["'`]\]\s*=/gi,
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
      patterns: [/\.__proto__\s*[=\[]/g, /\[["']__proto__["']\]/g, /constructor\.prototype/g, /Object\.prototype\[/g],
      description: '객체의 __proto__나 constructor.prototype을 수정하면 애플리케이션 전체 객체가 오염될 수 있습니다.',
      recommendation: 'Object.create(null)로 프로토타입 없는 객체를 사용하거나, 입력 키값을 검증하세요.',
    },

    // ════════════════════════════════════════
    // Open Redirect
    // ════════════════════════════════════════
    JS_OPEN_REDIRECT: {
      id: 'JS_OPEN_REDIRECT',
      name: '검증 없는 URL 리다이렉트',
      severity: 'MEDIUM',
      cwe: 'CWE-601',
      category: 'Open Redirect',
      type: 'js_pattern',
      patterns: [/location\.href\s*=/g, /location\.replace\s*\(/g, /location\.assign\s*\(/g, /window\.open\s*\(/g],
      description: '사용자 입력 기반의 URL 리다이렉트는 피싱 공격에 악용될 수 있습니다.',
      recommendation: '리다이렉트 전 허용 도메인 화이트리스트를 검증하세요.',
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
        /\bMD5\s*\(/gi,
        /CryptoJS\.MD5/g,
        /CryptoJS\.SHA1\b/g,
        /\bsha1\s*\(/gi,
        /\bRC4\s*\(/gi,
        /forge\.md\.md5/g,
        /["'`](?:md5|sha1|sha-1|rc4|des|3des)["'`]/gi,
        /createHash\s*\(\s*["'`](?:md5|sha1)["'`]\)/gi,
      ],
      description: 'MD5, SHA-1, RC4, DES는 충돌 공격 또는 브루트포스에 취약한 구식 알고리즘입니다.',
      recommendation: 'SHA-256 이상(SHA-3, bcrypt, Argon2)을 사용하고, Web Crypto API를 권장합니다.',
    },
    INSECURE_RANDOM: {
      id: 'INSECURE_RANDOM',
      name: 'Math.random() 보안 목적 사용',
      severity: 'MEDIUM',
      cwe: 'CWE-338',
      category: 'Cryptography',
      type: 'js_pattern',
      patterns: [
        /Math\.random\s*\(\s*\).*(?:token|secret|key|session|nonce|id|salt)/gi,
        /(?:token|secret|key|session|nonce|salt).*Math\.random\s*\(\s*\)/gi,
        /Math\.random\s*\(\s*\)\.toString\s*\(\s*36\s*\)\.slice/g,
      ],
      description: 'Math.random()은 암호학적으로 안전하지 않아 예측 가능한 값을 생성합니다.',
      recommendation: 'crypto.getRandomValues() 또는 crypto.randomUUID()를 사용하세요.',
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
      selectors: ['img[src^="http://"]','script[src^="http://"]','link[href^="http://"]','iframe[src^="http://"]','form[action^="http://"]','video[src^="http://"]','audio[src^="http://"]'],
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
        /["'`]ws:\/\/[^"'`\s]+["'`]/g,
      ],
      description: 'ws:// WebSocket은 암호화되지 않아 네트워크 상에서 데이터를 도청당할 수 있습니다.',
      recommendation: 'wss:// (WebSocket Secure)를 사용하세요.',
    },
    FORM_HTTP_ACTION: {
      id: 'FORM_HTTP_ACTION',
      name: 'HTTP로 폼 데이터 전송',
      severity: 'HIGH',
      cwe: 'CWE-319',
      category: 'Transport Security',
      type: 'dom_selector',
      selectors: ['form[action^="http://"]'],
      description: 'HTTP 폼 전송은 평문으로 데이터가 전달되어 중간자 공격으로 탈취될 수 있습니다.',
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
    MISSING_CLICKJACKING_PROTECTION: {
      id: 'MISSING_CLICKJACKING_PROTECTION',
      name: '클릭재킹 방어 헤더 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-1021',
      category: 'Security Headers',
      type: 'meta_check',
      metaTarget: 'xframe',
      description: 'X-Frame-Options 또는 CSP frame-ancestors 설정이 없으면 iframe에 페이지를 삽입하여 클릭재킹 공격이 가능합니다.',
      recommendation: 'X-Frame-Options: DENY 헤더 또는 CSP frame-ancestors \'none\'을 설정하세요.',
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
      type: 'dom_selector',
      selectors: [
        'script[src^="http"]:not([integrity])',
        'script[src^="//"]:not([integrity])',
        'link[rel="stylesheet"][href^="http"]:not([integrity])',
        'link[rel="stylesheet"][href^="//"]:not([integrity])',
      ],
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
      selectors: ['iframe:not([sandbox])'],
      description: 'sandbox 속성이 없는 iframe은 스크립트 실행, 폼 제출, 팝업 등을 제한 없이 허용합니다.',
      recommendation: 'iframe에 sandbox="allow-scripts allow-same-origin" 등 최소 권한만 부여하세요.',
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
      ],
      description: 'Access-Control-Allow-Origin: * 설정은 모든 도메인에서 API에 접근할 수 있게 해 데이터 탈취 위험이 있습니다.',
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
        /\bdebugger\b/g,
        /console\s*\.\s*log\s*\([^)]*(?:password|token|secret|key|auth|credential)[^)]*\)/gi,
        /console\s*\.\s*(?:warn|error|info|debug)\s*\([^)]*(?:password|token|secret)[^)]*\)/gi,
      ],
      description: 'debugger 문이나 민감 정보가 포함된 console.log는 프로덕션에서 보안 정보를 노출할 수 있습니다.',
      recommendation: '배포 전 debugger 문과 민감 정보 로그를 모두 제거하세요.',
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
          if (findings.length >= 10) break;
        }
        if (findings.length >= 10) break;
      }
      if (findings.length >= 10) break;
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
          if (findings.length >= 10) return;
          const tag = el.tagName.toLowerCase();
          const attr = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('action') || '';
          findings.push({
            source: 'DOM',
            element: tag,
            attribute: attr,
            snippet: el.outerHTML.slice(0, 140),
          });
        });
      } catch (_) { /* 잘못된 셀렉터 무시 */ }
    }
    return findings;
  }

  // ─── 쿠키 분석 ─────────────────────────────────
  function analyzeCookies() {
    const cookieStr = document.cookie;
    if (!cookieStr) return [];
    const cookies = cookieStr.split(';').map(c => c.trim());
    const findings = [];
    cookies.forEach(cookie => {
      const name = cookie.split('=')[0].trim();
      if (name && findings.length < 5) {
        findings.push({
          source: 'Cookie',
          snippet: `쿠키 "${name}" — JS에서 접근 가능 (HttpOnly 미설정 의심)`,
          name,
        });
      }
    });
    return findings;
  }

  // ─── URL 파라미터 민감정보 확인 ───────────────────
  function checkSensitiveInURL() {
    const sensitiveKeys = ['token','password','passwd','pwd','secret','key','auth','api_key','apikey','access_token','private_key','credential','jwt','session_id'];
    const findings = [];
    try {
      const params = new URLSearchParams(location.search);
      for (const key of params.keys()) {
        const keyLower = key.toLowerCase();
        if (sensitiveKeys.some(s => keyLower.includes(s))) {
          findings.push({
            source: 'URL',
            snippet: `URL 쿼리 파라미터에 민감 키: ?${key}=*** (값은 마스킹됨)`,
          });
        }
      }
      // URL fragment에서도 확인
      const hash = location.hash;
      if (hash) {
        const hashParams = new URLSearchParams(hash.slice(1));
        for (const key of hashParams.keys()) {
          const keyLower = key.toLowerCase();
          if (sensitiveKeys.some(s => keyLower.includes(s))) {
            findings.push({
              source: 'URL Fragment',
              snippet: `URL fragment에 민감 키: #${key}=*** (값은 마스킹됨)`,
            });
          }
        }
      }
    } catch (_) {}
    return findings;
  }

  // ─── 보안 헤더 메타 태그 확인 ─────────────────────
  function checkSecurityMeta(rule) {
    if (rule.metaTarget === 'csp') {
      const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      if (cspMeta) return null;
      return [{ source: 'HTML Meta', snippet: 'Content-Security-Policy 메타 태그가 존재하지 않습니다.' }];
    }
    if (rule.metaTarget === 'xframe') {
      // X-Frame-Options는 HTTP 헤더로만 설정 가능 → CSP의 frame-ancestors로 대체 확인
      const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      if (cspMeta) {
        const content = cspMeta.getAttribute('content') || '';
        if (content.includes('frame-ancestors')) return null;
      }
      // 실제로 iframe 내부에서 실행 중인지도 확인
      try {
        if (window.top !== window.self) {
          return [{ source: 'Frame Detection', snippet: '이 페이지는 현재 iframe 안에서 실행 중이며, 클릭재킹 방어가 없습니다.' }];
        }
      } catch (_) {
        return [{ source: 'Frame Detection', snippet: '페이지가 cross-origin iframe 안에 있을 수 있습니다 (window.top 접근 차단됨).' }];
      }
      return [{ source: 'HTML Meta', snippet: 'X-Frame-Options 또는 CSP frame-ancestors 설정이 감지되지 않았습니다.' }];
    }
    return null;
  }

  // ─── 인라인/외부 스크립트 소스 수집 ──────────────
  function collectScriptSources() {
    const sources = [];

    // 인라인 <script> 태그
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

    // 인라인 이벤트 핸들러 값
    const inlineEvents = ['onclick','onerror','onload','onmouseover','onfocus','onsubmit','onkeydown','onkeyup'];
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

    // meta content도 수집 (CSP unsafe-inline 등)
    document.querySelectorAll('meta[content]').forEach(meta => {
      const content = meta.getAttribute('content') || '';
      if (content.length > 0) {
        sources.push({ code: content, source: `meta[${meta.getAttribute('name') || meta.getAttribute('http-equiv') || ''}]` });
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
