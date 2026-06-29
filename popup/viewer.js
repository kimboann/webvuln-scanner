/**
 * viewer.js
 * WebVuln Scanner 소스 코드 뷰어 스크립트
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url');
  const targetLine = parseInt(urlParams.get('line'), 10) || null;

  const filePathEl = document.getElementById('file-path');
  const lineInfoEl = document.getElementById('line-info');
  const loadingEl = document.getElementById('loading');
  const codeContainer = document.getElementById('code-container');
  const lineNumbersEl = document.getElementById('line-numbers');
  const codeLinesEl = document.getElementById('code-lines');

  if (!targetUrl) {
    loadingEl.textContent = '대상 URL이 지정되지 않았습니다.';
    return;
  }

  filePathEl.textContent = targetUrl;
  if (targetLine) {
    lineInfoEl.textContent = `Line ${targetLine}`;
  }

  try {
    let sourceCode = '';

    // 인라인 스크립트가 아닌 실제 외부 파일 로드 시 background에 요청
    if (targetUrl.startsWith('http://') || targetUrl.startsWith('https://')) {
      const res = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'FETCH_EXTERNAL_SCRIPT', url: targetUrl }, (response) => {
          resolve(response);
        });
      });

      if (res && res.success && res.text) {
        sourceCode = res.text;
      } else {
        throw new Error(res?.error || '소스를 다운로드할 수 없습니다.');
      }
    } else {
      // 인라인 스크립트일 경우 점검 탭의 HTML을 직접 가져와야 함
      // 편의상 팝업에서 인라인일 경우 소스를 같이 전달받거나, 탭의 HTML을 가져와 파싱할 수 있으나
      // 기본적으로 외부 스크립트 분석을 주로 타겟팅합니다.
      loadingEl.textContent = '인라인 스크립트 뷰어는 해당 페이지 소스보기로 대체 지원합니다.';
      return;
    }

    loadingEl.style.display = 'none';
    codeContainer.style.display = 'flex';

    const lines = sourceCode.split('\n');
    let lineNumsHtml = '';
    
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      lineNumsHtml += `${lineNum}\n`;

      const lineDiv = document.createElement('span');
      lineDiv.className = 'code-line';
      lineDiv.id = `line-${lineNum}`;
      lineDiv.textContent = line || ' '; // 빈 줄도 공간차지하게 처리

      if (targetLine && lineNum === targetLine) {
        lineDiv.classList.add('highlight');
      }

      codeLinesEl.appendChild(lineDiv);
    });

    lineNumbersEl.textContent = lineNumsHtml;

    // 타겟 라인으로 스크롤 이동
    if (targetLine) {
      setTimeout(() => {
        const targetEl = document.getElementById(`line-${targetLine}`);
        if (targetEl) {
          targetEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
      }, 300);
    }

  } catch (err) {
    loadingEl.textContent = `오류 발생: ${err.message}`;
  }
});
