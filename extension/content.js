/**
 * Lateryx Browser Extension - Content Script
 * Supports:
 * 1. GitHub PR pages (Checks GitHub API)
 * 2. Localhost pages (Checks local Lateryx server)
 */

class LaterxyContentScript {
    constructor() {
        this.badgeInjected = false;
        this.devServerUrl = 'http://localhost:9991/status';
        this.init();
    }

    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.onPageLoad());
        } else {
            this.onPageLoad();
        }

        this.observePageChanges();
    }

    onPageLoad() {
        if (this.isGitHubPR()) {
            this.injectGitHubBadge();
        } else if (this.isLocalhost()) {
            this.injectLocalhostBadge();
        }
    }

    isGitHubPR() {
        return window.location.hostname === 'github.com' &&
            window.location.pathname.match(/\/pull\/\d+/);
    }

    isLocalhost() {
        return window.location.hostname === 'localhost' ||
            window.location.hostname === '127.0.0.1';
    }

    observePageChanges() {
        // GitHub uses Turbo, Localhost might use React/Next.js hydration
        const observer = new MutationObserver(() => {
            if (this.isGitHubPR() && !this.badgeInjected) {
                this.injectGitHubBadge();
            }
            // For localhost, we execute once on load usually, but could re-check
        });

        observer.observe(document.body, { childList: true, subtree: true });
        document.addEventListener('turbo:load', () => {
            this.badgeInjected = false;
            if (this.isGitHubPR()) this.injectGitHubBadge();
        });
    }

    // --- GitHub Logic ---

    async injectGitHubBadge() {
        const prHeader = document.querySelector('.gh-header-show');
        if (!prHeader || this.badgeInjected) return;

        const badge = this.createBadgeElement();
        const actionsContainer = prHeader.querySelector('.gh-header-actions');

        if (actionsContainer) actionsContainer.prepend(badge.container);
        else prHeader.appendChild(badge.container);

        this.badgeInjected = true;
        await this.updateGitHubStatus(badge.element);
    }

    async updateGitHubStatus(badgeElement) {
        try {
            const match = window.location.pathname.match(/\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
            if (!match) return;
            const [, owner, repo, prNumber] = match;

            // Fetch status (logic from previous version)
            const status = await this.getGitHubCheckStatus(owner, repo, prNumber);
            this.updateBadgeUI(badgeElement, status);
        } catch (e) {
            this.setBadgeError(badgeElement);
        }
    }

    // --- Localhost Logic ---

    async injectLocalhostBadge() {
        if (document.getElementById('lateryx-dev-overlay')) return;

        // For localhost, we inject a floating badge in the bottom-right
        const container = document.createElement('div');
        container.id = 'lateryx-dev-overlay';
        container.className = 'lateryx-overlay';
        container.innerHTML = `
            <div class="lateryx-badge loading">
                <span class="lateryx-icon">🛡️</span>
                <span class="lateryx-text">Lateryx Dev</span>
            </div>
        `;
        document.body.appendChild(container);

        // Check local server status
        setInterval(() => this.checkLocalServer(container), 5000); // Poll every 5s
        this.checkLocalServer(container);
    }

    async checkLocalServer(container) {
        const badge = container.querySelector('.lateryx-badge');
        try {
            const response = await fetch(this.devServerUrl);
            if (!response.ok) throw new Error('Server offline');

            const data = await response.json();

            if (data.is_safe) {
                badge.className = 'lateryx-badge safe';
                badge.innerHTML = `<span class="lateryx-icon">✅</span><span class="lateryx-text">Infra Secure</span>`;
            } else {
                badge.className = 'lateryx-badge unsafe';
                const count = data.findings ? data.findings.length : 0;
                badge.innerHTML = `<span class="lateryx-icon">⚠️</span><span class="lateryx-text">${count} Issues</span>`;
            }
        } catch (e) {
            // Server probably not running
            badge.className = 'lateryx-badge not-configured';
            badge.innerHTML = `<span class="lateryx-icon">💤</span><span class="lateryx-text">Sentinel Offline</span>`;
            badge.title = "Run 'lateryx serve' to activate real-time checking";
        }
    }

    // --- Helpers ---

    createBadgeElement() {
        const container = document.createElement('div');
        container.className = 'lateryx-badge-container';
        container.innerHTML = `
            <div class="lateryx-badge loading">
                <span class="lateryx-icon">🛡️</span>
                <span class="lateryx-text">Checking...</span>
            </div>
        `;
        return { container, element: container.querySelector('.lateryx-badge') };
    }

    updateBadgeUI(badge, status) {
        if (!status) {
            badge.className = 'lateryx-badge not-configured';
            badge.innerHTML = `<span class="lateryx-icon">🔧</span><span class="lateryx-text">Add Lateryx</span>`;
        } else if (status.isSafe) {
            badge.className = 'lateryx-badge safe';
            badge.innerHTML = `<span class="lateryx-icon">✅</span><span class="lateryx-text">Safe to Ship</span>`;
        } else {
            badge.className = 'lateryx-badge unsafe';
            badge.innerHTML = `<span class="lateryx-icon">⚠️</span><span class="lateryx-text">${status.findings} Issues</span>`;
        }

        if (status && status.url) {
            badge.onclick = () => window.open(status.url, '_blank');
        }
    }

    setBadgeError(badge) {
        badge.className = 'lateryx-badge error';
        badge.innerHTML = `<span class="lateryx-icon">❌</span><span class="lateryx-text">Error</span>`;
    }

    async getGitHubCheckStatus(owner, repo, prNumber) {
        // Re-using existing logic...
        // Fetch PR, Get Head SHA, Get Check Runs...
        // For brevity in this artifact, reusing simplified logic:
        try {
            const prData = await (await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`)).json();
            const headSha = prData.head.sha;
            const checksData = await (await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${headSha}/check-runs`)).json();

            const check = checksData.check_runs.find(c => c.name.toLowerCase().includes('lateryx'));
            if (!check) return null;

            let findings = 0;
            if (check.output && check.output.text) {
                const match = check.output.text.match(/Breaches Detected[:\s]+(\d+)/i);
                if (match) findings = parseInt(match[1], 10);
            }

            return { isSafe: check.conclusion === 'success', findings, url: check.html_url };
        } catch { return null; }
    }
}

new LaterxyContentScript();
