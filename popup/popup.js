/**
 * popup.js
 * WebVuln Scanner 팝업 로직
 * content.js와 메시지로 통신하여 분석 결과를 UI에 렌더링합니다.
 */

'use strict';

// ── KISA 주요정보통신기반시설 웹 기술적 취약점 매핑 테이블 ─────────────────
const KISA_MAPPING = {
  // 1. 코드 인젝션
  JS_EVAL: { code: '1. 코드 인젝션', name: 'Code Injection' },
  JS_SETTIMEOUT_STRING: { code: '1. 코드 인젝션', name: 'Code Injection' },
  JS_PROTO_POLLUTION: { code: '1. 코드 인젝션', name: 'Code Injection (Prototype Pollution)' },

  // 4. 에러 페이지 적용 미흡
  // (디버그 코드나 스택 트레이스 노출 방지 연계)
  DEBUG_CODE: { code: '4. 에러 페이지 적용 미흡', name: 'Error Page Misconfiguration' },

  // 5. 정보 누출
  JS_HARDCODED_SECRET: { code: '5. 정보 누출', name: 'Information Disclosure (Secrets)' },
  SENSITIVE_COMMENT: { code: '5. 정보 누출', name: 'Information Disclosure (Sensitive Comments)' },
  INFO_DISCLOSURE_COMMENT: { code: '5. 정보 누출', name: 'Information Disclosure (Internal Path)' },

  // 6. 크로스사이트 스크립팅 (XSS)
  JS_INNER_HTML: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (XSS)' },
  JS_DOM_SOURCE_TO_SINK: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (DOM XSS)' },
  JS_DOCUMENT_WRITE: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (XSS)' },
  JS_JAVASCRIPT_URI: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (XSS)' },
  DOM_JAVASCRIPT_HREF: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (XSS)' },
  DOM_INLINE_EVENT: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (XSS)' },
  REACT_DANGEROUS_HTML: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (Framework XSS)' },
  JSONP_USAGE: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (JSONP)' },
  TEMPLATE_INJECTION: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (Template Injection)' },
  JS_OPEN_REDIRECT: { code: '6. 크로스사이트 스크립팅', name: 'Cross-Site Scripting (Redirect XSS)' },

  // 11. 불충분한 권한 검증
  SENSITIVE_STORAGE: { code: '11. 불충분한 권한 검증', name: 'Insufficient Authorization (Local Storage)' },

  // 12. 취약한 비밀번호 복구 절차
  INSECURE_RANDOM: { code: '12. 취약한 비밀번호 복구 절차', name: 'Weak Password Recovery (Math.random)' },

  // 13. 프로세스 검증 누락
  // (CORS 와일드카드는 프로세스 호출 우회보다 불필요한 HTTP Method 악용에 적합하여 21번으로 매핑)

  // 15. 파일 다운로드
  SENSITIVE_IN_URL: { code: '15. 파일 다운로드', name: 'File Download (Sensitive Query Parameter)' },

  // 16. 불충분한 세션 관리
  COOKIE_INSECURE: { code: '16. 불충분한 세션 관리', name: 'Insufficient Session Management (HttpOnly Missing)' },
  COOKIE_JS_SET: { code: '16. 불충분한 세션 관리', name: 'Insufficient Session Management (JS Cookie Set)' },

  // 17. 데이터 평문 전송
  MIXED_CONTENT: { code: '17. 데이터 평문 전송', name: 'Plaintext Transmission (Mixed Content)' },
  WEBSOCKET_INSECURE: { code: '17. 데이터 평문 전송', name: 'Plaintext Transmission (Insecure WebSocket)' },
  FORM_HTTP_ACTION: { code: '17. 데이터 평문 전송', name: 'Plaintext Transmission (HTTP Form)' },

  // 18. 쿠키 변조
  // (서명되지 않은 JS 쿠키 변조 및 위조)
  COOKIE_JS_SET_SIGNCHECK: { code: '18. 쿠키 변조', name: 'Cookie Modification' },

  // 19. 관리자 페이지 노출
  INFO_DISCLOSURE_COMMENT: { code: '19. 관리자 페이지 노출', name: 'Administrator Page Exposure (Internal Path)' },

  // 20. 자동화 공격
  // (CSP 설정을 통한 비정상 스크립트 실행 통제)
  MISSING_CSP: { code: '20. 자동화 공격', name: 'Automated Attacks (CSP Missing)' },
  CSP_UNSAFE: { code: '20. 자동화 공격', name: 'Automated Attacks (CSP Unsafe)' },

  // 21. 불필요한 Method 악용
  CORS_WILDCARD: { code: '21. 불필요한 Method 악용', name: 'Arbitrary Method Abuse (CORS Wildcard)' },

  // 기타 웹 보안 표준 매핑 (CWE 연계)
  WEAK_CRYPTO: { code: 'WEB-STD', name: '취약한 암호 알고리즘 사용' },
  SRI_MISSING: { code: 'WEB-STD', name: '서브리소스 무결성(SRI) 누락' },
  IFRAME_NO_SANDBOX: { code: 'WEB-STD', name: 'Iframe 보안 설정 미흡' },
  IFRAME_OVERPERMISSIVE_SANDBOX: { code: 'WEB-STD', name: 'Iframe 보안 설정 미흡' },
  MISSING_CLICKJACKING_PROTECTION: { code: 'WEB-STD', name: '클릭재킹 방어 미흡' }
};

// ── DOM 참조 ──────────────────────────────────────
const $ = id => document.getElementById(id);
const statusDot    = $('status-dot');
const pageInfo     = $('page-info');
const pageUrlEl    = $('page-url');
const httpsBadge   = $('https-badge');
const scanBtn      = $('scan-btn');
const btnText      = $('btn-text');
const loadingEl    = $('loading');
const resultClean  = $('result-clean');
const summaryEl    = $('summary');
const filterTabs   = $('filter-tabs');
const vulnList     = $('vuln-list');
const errorState   = $('error-state');
const errorMsg     = $('error-msg');
const scanTime     = $('scan-time');
const detailModal  = $('detail-modal');
const modalClose   = $('modal-close');

// ── 상태 ──────────────────────────────────────────
let scanData = null;
let currentFilter = 'ALL';
let currentTabId = null;

// ── 초기화 ────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('탭 정보를 가져올 수 없습니다.');

    currentTabId = tab.id;
    const url = tab.url || '';
    const isHTTPS = url.startsWith('https://');

    // 페이지 정보 표시
    const shortUrl = url.replace(/^https?:\/\//, '').slice(0, 50) + (url.length > 50 ? '…' : '');
    pageUrlEl.textContent = shortUrl;
    if (isHTTPS) httpsBadge.classList.remove('hidden');
    pageInfo.classList.remove('hidden');

    // chrome:// 같은 내부 페이지는 스캔 불가
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      setError('이 페이지는 스캔할 수 없습니다 (브라우저 내부 페이지)');
    }

  } catch (e) {
    console.error(e);
  }
});

// ── 스캔 버튼 ─────────────────────────────────────
scanBtn.addEventListener('click', startScan);

async function startScan() {
  if (!currentTabId) return;

  showLoading();

  try {
    // content script 주입 후 분석 요청
    await chrome.scripting.executeScript({
      target: { tabId: currentTabId },
      files: ['content/content.js'],
    });

    const response = await chrome.tabs.sendMessage(currentTabId, { action: 'START_SCAN' });

    if (!response || !response.success) {
      throw new Error(response?.error || '분석에 실패했습니다.');
    }

    scanData = response.data;
    renderResults(scanData);

  } catch (err) {
    console.error('[WebVuln Scanner]', err);
    let msg = err.message || '알 수 없는 오류';
    if (msg.includes('Cannot access') || msg.includes('could not be cloned')) {
      msg = '이 페이지에서 스크립트 실행이 허용되지 않습니다.';
    }
    setError(msg);
  }
}

// ── 결과 렌더링 ──────────────────────────────────
function renderResults(data) {
  hideAll();

  // 요약 카드
  updateSummary(data.summary);
  summaryEl.classList.remove('hidden');

  const scanned = new Date(data.scannedAt);
  scanTime.textContent = `스캔: ${scanned.toLocaleTimeString('ko-KR')}`;

  if (data.totalVulns === 0) {
    statusDot.className = 'status-dot done';
    resultClean.classList.remove('hidden');
    return;
  }

  // 심각도별 상태
  if (data.summary.CRITICAL > 0) statusDot.className = 'status-dot error';
  else if (data.summary.HIGH > 0) statusDot.className = 'status-dot warning';
  else statusDot.className = 'status-dot warning';

  // 필터 탭
  filterTabs.classList.remove('hidden');
  renderVulnList(data.results, 'ALL');

  scanBtn.disabled = false;
  btnText.textContent = '재스캔';
}

function updateSummary(summary) {
  $('cnt-critical').querySelector('.summary-num').textContent = summary.CRITICAL;
  $('cnt-high').querySelector('.summary-num').textContent     = summary.HIGH;
  $('cnt-medium').querySelector('.summary-num').textContent   = summary.MEDIUM;
  $('cnt-low').querySelector('.summary-num').textContent      = summary.LOW;
}

function renderVulnList(results, filter) {
  currentFilter = filter;
  vulnList.innerHTML = '';

  const filtered = filter === 'ALL'
    ? results
    : results.filter(r => r.rule.severity === filter);

  if (filtered.length === 0) {
    vulnList.innerHTML = `<p style="text-align:center;color:var(--text-muted);font-size:12px;padding:16px 0;">해당 심각도의 취약점이 없습니다</p>`;
    vulnList.classList.remove('hidden');
    return;
  }

  filtered.forEach((item, idx) => {
    const card = createVulnCard(item, idx);
    vulnList.appendChild(card);
  });

  vulnList.classList.remove('hidden');
}

function createVulnCard(item, idx) {
  const { rule, count } = item;
  const sev = rule.severity.toLowerCase();

  // KISA 코드 탐색
  const kisa = KISA_MAPPING[rule.id] || { code: 'N/A', name: '기타 웹 보안 정책' };

  const card = document.createElement('div');
  card.className = `vuln-card ${sev}`;
  card.style.animationDelay = `${idx * 0.05}s`;
  card.setAttribute('role', 'button');
  card.setAttribute('tabindex', '0');
  card.setAttribute('id', `vuln-card-${rule.id}`);

  card.innerHTML = `
    <div class="vuln-card-left">
      <div class="vuln-name">[${escapeHtml(kisa.code)}] ${escapeHtml(rule.name)}</div>
      <div class="vuln-meta">
        <span class="severity-badge ${sev}">${rule.severity}</span>
        <span class="cwe-tag">${rule.cwe}</span>
        <span class="cat-tag">${escapeHtml(kisa.name)}</span>
      </div>
    </div>
    <div class="vuln-card-right" style="display:flex;align-items:center;gap:6px">
      <span class="vuln-count">${count}</span>
      <svg class="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none">
        <path d="M9 18l6-6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
  `;

  card.addEventListener('click', () => openModal(item));
  card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') openModal(item); });

  return card;
}

// ── 상세 모달 ─────────────────────────────────────
function openModal(item) {
  const { rule, count, findings } = item;
  const sev = rule.severity.toLowerCase();
  
  // KISA 정보 탐색
  const kisa = KISA_MAPPING[rule.id] || { code: 'N/A', name: '기타 웹 보안 정책' };

  $('modal-severity-badge').className = `severity-badge ${sev}`;
  $('modal-severity-badge').textContent = rule.severity;
  $('modal-title').textContent = rule.name;
  
  // 모달 메타 필드 데이터 입력
  $('modal-cwe').textContent = rule.cwe;
  $('modal-category').textContent = `주요기반시설: ${kisa.code}`;
  $('modal-category').title = kisa.name;
  $('modal-count').textContent = `${count}건 탐지`;
  
  // 설명 및 권고사항
  const fullDescription = `[KISA 웹 기술평가기준: ${kisa.code} - ${kisa.name}]\n\n${rule.description}`;
  $('modal-description').textContent = fullDescription;
  $('modal-recommendation').textContent = rule.recommendation;

  // findings
  const findingsContainer = $('modal-findings');
  findingsContainer.innerHTML = '';

  if (findings && findings.length > 0) {
    findings.forEach((f) => {
      const item = document.createElement('div');
      item.className = 'finding-item';
      item.innerHTML = `
        <div class="finding-source">${escapeHtml(f.source || 'DOM')}${f.line ? ` · Line ${f.line}` : ''}</div>
        <div class="finding-snippet">${escapeHtml(f.snippet || f.attribute || '(정보 없음)')}</div>
      `;
      findingsContainer.appendChild(item);
    });
    $('modal-findings-section').classList.remove('hidden');
  } else {
    $('modal-findings-section').classList.add('hidden');
  }

  detailModal.classList.remove('hidden');
}

modalClose.addEventListener('click', closeModal);
detailModal.addEventListener('click', e => {
  if (e.target === detailModal) closeModal();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

function closeModal() {
  detailModal.classList.add('hidden');
}

// ── 필터 탭 ───────────────────────────────────────
document.querySelectorAll('.filter-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    if (scanData) {
      renderVulnList(scanData.results, tab.dataset.filter);
    }
  });
});

// ── UI 상태 관리 ──────────────────────────────────
function showLoading() {
  hideAll();
  scanBtn.disabled = true;
  btnText.textContent = '분석 중...';
  statusDot.className = 'status-dot scanning';
  loadingEl.classList.remove('hidden');
}

function hideAll() {
  loadingEl.classList.add('hidden');
  resultClean.classList.add('hidden');
  summaryEl.classList.add('hidden');
  filterTabs.classList.add('hidden');
  vulnList.classList.add('hidden');
  errorState.classList.add('hidden');
  scanBtn.disabled = false;
}

function setError(msg) {
  hideAll();
  statusDot.className = 'status-dot error';
  errorMsg.textContent = msg;
  errorState.classList.remove('hidden');
  scanBtn.disabled = false;
  btnText.textContent = '재시도';
}

// ── 유틸 ──────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
