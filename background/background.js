/**
 * background.js (Service Worker)
 * 팝업과 콘텐츠 스크립트 사이의 메시지 브릿지 역할
 * Manifest V3 Service Worker
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 현재는 직접 통신 방식 사용 (popup → content script)
  // 필요시 추가 백그라운드 로직 구현 가능
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
