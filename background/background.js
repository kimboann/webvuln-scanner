/**
 * background.js (Service Worker)
 * 팝업과 콘텐츠 스크립트 사이의 메시지 브릿지 역할
 * Manifest V3 Service Worker
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'FETCH_EXTERNAL_SCRIPT') {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8초 타임아웃

    fetch(message.url, { signal: controller.signal })
      .then(res => {
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        return res.text();
      })
      .then(text => sendResponse({ success: true, text }))
      .catch(err => {
        clearTimeout(timeoutId);
        sendResponse({ success: false, error: err.message });
      });
    return true; // 비동기 응답 유지
  }
  return false;
});

// 확장 프로그램 설치/업데이트 시 초기화
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[WebVuln Scanner] 설치 완료');
  } else if (details.reason === 'update') {
    console.log('[WebVuln Scanner] 업데이트 완료:', details.previousVersion, '→', chrome.runtime.getManifest().version);
  }
});
