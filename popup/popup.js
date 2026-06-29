/**
 * popup.js
 * WebVuln Scanner 팝업 로직
 * content.js와 메시지로 통신하여 분석 결과를 UI에 렌더링합니다.
 */

'use strict';

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

  const card = document.createElement('div');
  card.className = `vuln-card ${sev}`;
  card.style.animationDelay = `${idx * 0.05}s`;
  card.setAttribute('role', 'button');
  card.setAttribute('tabindex', '0');
  card.setAttribute('id', `vuln-card-${rule.id}`);

  card.innerHTML = `
    <div class="vuln-card-left">
      <div class="vuln-name">${escapeHtml(rule.name)}</div>
      <div class="vuln-meta">
        <span class="severity-badge ${sev}">${rule.severity}</span>
        <span class="cwe-tag">${rule.cwe}</span>
        <span class="cat-tag">${escapeHtml(rule.category)}</span>
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

  $('modal-severity-badge').className = `severity-badge ${sev}`;
  $('modal-severity-badge').textContent = rule.severity;
  $('modal-title').textContent = rule.name;
  $('modal-cwe').textContent = rule.cwe;
  $('modal-category').textContent = rule.category;
  $('modal-count').textContent = `${count}건 탐지`;
  $('modal-description').textContent = rule.description;
  $('modal-recommendation').textContent = rule.recommendation;

  // findings
  const findingsContainer = $('modal-findings');
  findingsContainer.innerHTML = '';

  if (findings && findings.length > 0) {
    findings.forEach((f, i) => {
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
