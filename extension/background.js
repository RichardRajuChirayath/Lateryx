/**
 * Lateryx Browser Extension - Background Service Worker
 * Handles extension lifecycle and cross-tab communication
 */

// Extension installation handler
chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        console.log('Lateryx extension installed');

        // Open welcome page
        chrome.tabs.create({
            url: 'https://richardrajuchirayath.github.io/Lateryx/documentation.html'
        });
    } else if (details.reason === 'update') {
        console.log('Lateryx extension updated to version', chrome.runtime.getManifest().version);
    }
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_SETTINGS') {
        chrome.storage.sync.get(['githubToken', 'autoInject'], (settings) => {
            sendResponse(settings);
        });
        return true; // Keep channel open for async response
    }

    if (message.type === 'UPDATE_BADGE') {
        updateExtensionBadge(message.status, sender.tab.id);
    }

    if (message.type === 'OPEN_SETTINGS') {
        chrome.runtime.openOptionsPage();
    }
});

// Update extension icon badge based on security status
function updateExtensionBadge(status, tabId) {
    const badgeConfig = {
        safe: { text: '✓', color: '#238636' },
        unsafe: { text: '!', color: '#da3633' },
        loading: { text: '...', color: '#6e7681' },
        none: { text: '', color: '#30363d' }
    };

    const config = badgeConfig[status] || badgeConfig.none;

    chrome.action.setBadgeText({ text: config.text, tabId });
    chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

// Listen for tab updates to check for GitHub pages
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        const isGitHub = tab.url.includes('github.com') && tab.url.includes('/pull/');
        const isLocalhost = tab.url.includes('localhost') || tab.url.includes('127.0.0.1');

        if (isGitHub || isLocalhost) {
            // On a PR page or Localhost - icon becomes active
            chrome.action.setIcon({
                tabId,
                path: {
                    "128": "icons/icon-128.png"
                }
            });
        }
    }
});

// Handle keyboard shortcuts
chrome.commands.onCommand.addListener((command) => {
    if (command === 'toggle-lateryx') {
        chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
            if (tab && tab.url.includes('github.com')) {
                chrome.tabs.sendMessage(tab.id, { type: 'TOGGLE_BADGE' });
            }
        });
    }
});

console.log('Lateryx background service worker initialized');
