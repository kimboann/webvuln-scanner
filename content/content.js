/**
 * content.js
 * 페이지 DOM 및 JavaScript 코드를 정적 분석하는 Content Script
 * popup.js의 요청을 받아 분석을 수행하고 결과를 반환합니다.
 */

(() => {
  'use strict';

  // ─── 취약점 탐지 규칙 ─────────────────────────────
  const VULN_RULES = {
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
      ],
      description: 'API 키, 패스워드 등 민감 정보가 소스 코드에 하드코딩되어 있습니다.',
      recommendation: '환경 변수나 비밀 관리 서비스를 사용하고 소스 코드에서 제거하세요.',
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
    COOKIE_INSECURE: {
      id: 'COOKIE_INSECURE',
      name: '안전하지 않은 쿠키 설정',
      severity: 'HIGH',
      cwe: 'CWE-614',
      category: 'Session Security',
      type: 'cookie',
      description: '쿠키에 Secure 또는 HttpOnly 속성이 없으면 세션 탈취 공격에 취약합니다.',
      recommendation: '쿠키 설정 시 Secure, HttpOnly, SameSite=Strict 속성을 반드시 추가하세요.',
    },
    MISSING_CSP: {
      id: 'MISSING_CSP',
      name: 'Content Security Policy (CSP) 누락',
      severity: 'MEDIUM',
      cwe: 'CWE-693',
      category: 'Security Headers',
      type: 'meta_check',
      metaName: 'content-security-policy',
      description: 'CSP 헤더/메타 태그가 없으면 XSS 및 데이터 인젝션 공격 방어가 불가능합니다.',
      recommendation: '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">를 추가하세요.',
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
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        if (findings.length >= 10) return;
        const tag = el.tagName.toLowerCase();
        const attr = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('action') || el.outerHTML.slice(0, 100);
        findings.push({
          source: 'DOM',
          element: tag,
          attribute: attr,
          snippet: el.outerHTML.slice(0, 120),
        });
      });
    }
    return findings;
  }

  // ─── 쿠키 분석 ─────────────────────────────────
  function analyzeCookies() {
    const cookieStr = document.cookie;
    if (!cookieStr) return [];
    const cookies = cookieStr.split(';').map(c => c.trim());
    // document.cookie로는 HttpOnly/Secure 플래그를 직접 확인 불가
    // 하지만 쿠키가 JS에서 접근 가능하다는 것 자체가 HttpOnly 미설정 증거
    const findings = [];
    cookies.forEach(cookie => {
      const name = cookie.split('=')[0];
      if (name && findings.length < 5) {
        findings.push({
          source: 'Cookie',
          snippet: `쿠키 "${name}" - JS에서 접근 가능 (HttpOnly 미설정 의심)`,
          name,
        });
      }
    });
    return findings;
  }

  // ─── CSP 메타 태그 확인 ────────────────────────
  function checkCSP() {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspMeta) return null; // CSP 있음, 취약점 없음
    return [{
      source: 'HTML Meta',
      snippet: 'CSP 메타 태그가 존재하지 않습니다.',
    }];
  }

  // ─── 인라인 스크립트 + 외부 스크립트 URL 수집 ──
  function collectScriptSources() {
    const sources = [];

    // 인라인 <script> 태그
    const scriptTags = document.querySelectorAll('script:not([src])');
    scriptTags.forEach((tag, i) => {
      const code = tag.textContent || '';
      if (code.trim().length > 0) {
        sources.push({ code, source: `inline-script[${i}]` });
      }
    });

    // 외부 스크립트 URL 자체를 코드로 처리 (URL에서 패턴 탐지)
    const externalScripts = document.querySelectorAll('script[src]');
    externalScripts.forEach(tag => {
      const src = tag.getAttribute('src') || '';
      sources.push({ code: src, source: `external-script: ${src}` });
    });

    // onclick/onerror 등 인라인 핸들러 값 수집
    const allElements = document.querySelectorAll('*');
    const inlineEvents = ['onclick','onerror','onload','onmouseover','onfocus','onsubmit'];
    const eventCode = [];
    allElements.forEach(el => {
      for (const ev of inlineEvents) {
        const val = el.getAttribute(ev);
        if (val) eventCode.push(val);
      }
    });
    if (eventCode.length > 0) {
      sources.push({ code: eventCode.join('\n'), source: 'inline-event-handlers' });
    }

    return sources;
  }

  // ─── 메인 분석 함수 ────────────────────────────
  function runAnalysis() {
    const results = [];
    const scriptSources = collectScriptSources();
    const pageUrl = location.href;
    const pageTitle = document.title;
    const isHTTPS = location.protocol === 'https:';

    for (const [ruleId, rule] of Object.entries(VULN_RULES)) {
      let findings = [];

      if (rule.type === 'js_pattern') {
        findings = analyzeJSPattern(rule, scriptSources);
      } else if (rule.type === 'dom_selector') {
        findings = analyzeDOMSelector(rule);
      } else if (rule.type === 'cookie') {
        findings = analyzeCookies();
      } else if (rule.type === 'meta_check') {
        const r = checkCSP();
        if (r) findings = r;
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
        HIGH: results.filter(r => r.rule.severity === 'HIGH').length,
        MEDIUM: results.filter(r => r.rule.severity === 'MEDIUM').length,
        LOW: results.filter(r => r.rule.severity === 'LOW').length,
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
    return true; // 비동기 응답 유지
  });

})();
