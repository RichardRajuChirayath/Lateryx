/**
 * Lateryx Browser Extension - Content Script
 * Injects security status badges directly into GitHub PR pages
 */

class LaterxyContentScript {
    constructor() {
        this.badgeInjected = false;
        this.init();
    }

    init() {
        // Wait for page to fully load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.onPageLoad());
        } else {
            this.onPageLoad();
        }

        // Watch for dynamic content changes (GitHub uses Turbo)
        this.observePageChanges();
    }

    onPageLoad() {
        // Check if we're on a PR page
        if (this.isPRPage()) {
            this.injectSecurityBadge();
        }
    }

    isPRPage() {
        return window.location.pathname.match(/\/pull\/\d+/);
    }

    observePageChanges() {
        // GitHub uses Turbo for navigation, so we need to watch for changes
        const observer = new MutationObserver((mutations) => {
            if (this.isPRPage() && !this.badgeInjected) {
                this.injectSecurityBadge();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Also listen for Turbo navigation events
        document.addEventListener('turbo:load', () => {
            this.badgeInjected = false;
            if (this.isPRPage()) {
                this.injectSecurityBadge();
            }
        });
    }

    async injectSecurityBadge() {
        // Find the PR header area
        const prHeader = document.querySelector('.gh-header-show');
        if (!prHeader || this.badgeInjected) return;

        // Create the Lateryx badge container
        const badgeContainer = document.createElement('div');
        badgeContainer.id = 'lateryx-badge';
        badgeContainer.className = 'lateryx-badge-container';
        badgeContainer.innerHTML = `
            <div class="lateryx-badge loading">
                <span class="lateryx-icon">🛡️</span>
                <span class="lateryx-text">Checking security...</span>
            </div>
        `;

        // Find a good insertion point
        const actionsContainer = prHeader.querySelector('.gh-header-actions');
        if (actionsContainer) {
            actionsContainer.prepend(badgeContainer);
        } else {
            prHeader.appendChild(badgeContainer);
        }

        this.badgeInjected = true;

        // Fetch and update status
        await this.updateBadgeStatus(badgeContainer);
    }

    async updateBadgeStatus(container) {
        try {
            // Parse PR info from URL
            const match = window.location.pathname.match(/\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
            if (!match) return;

            const [, owner, repo, prNumber] = match;

            // Get check status
            const status = await this.getCheckStatus(owner, repo, prNumber);

            const badge = container.querySelector('.lateryx-badge');

            if (status === null) {
                // Lateryx not configured
                badge.className = 'lateryx-badge not-configured';
                badge.innerHTML = `
                    <span class="lateryx-icon">🔧</span>
                    <span class="lateryx-text">Add Lateryx</span>
                `;
            } else if (status.isSafe) {
                badge.className = 'lateryx-badge safe';
                badge.innerHTML = `
                    <span class="lateryx-icon">✅</span>
                    <span class="lateryx-text">Safe to Ship</span>
                `;
            } else {
                badge.className = 'lateryx-badge unsafe';
                badge.innerHTML = `
                    <span class="lateryx-icon">⚠️</span>
                    <span class="lateryx-text">${status.findings} Issues</span>
                `;
            }

            // Add click handler
            badge.addEventListener('click', () => {
                if (status && status.url) {
                    window.open(status.url, '_blank');
                }
            });

        } catch (error) {
            console.error('Lateryx: Error updating badge', error);
            const badge = container.querySelector('.lateryx-badge');
            badge.className = 'lateryx-badge error';
            badge.innerHTML = `
                <span class="lateryx-icon">❌</span>
                <span class="lateryx-text">Error</span>
            `;
        }
    }

    async getCheckStatus(owner, repo, prNumber) {
        try {
            // Get PR data
            const prResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`
            );

            if (!prResponse.ok) return null;

            const prData = await prResponse.json();
            const headSha = prData.head.sha;

            // Get check runs
            const checksResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repo}/commits/${headSha}/check-runs`
            );

            if (!checksResponse.ok) return null;

            const checksData = await checksResponse.json();

            // Find Lateryx check
            const laterxyCheck = checksData.check_runs.find(check =>
                check.name.toLowerCase().includes('lateryx') ||
                check.name.toLowerCase().includes('security-scan')
            );

            if (!laterxyCheck) return null;

            const isSafe = laterxyCheck.conclusion === 'success';

            // Parse findings count
            let findings = 0;
            if (laterxyCheck.output && laterxyCheck.output.text) {
                const match = laterxyCheck.output.text.match(/Breaches[:\s]+(\d+)/i);
                if (match) findings = parseInt(match[1], 10);
            }

            return {
                isSafe,
                findings,
                url: laterxyCheck.html_url
            };

        } catch (error) {
            console.error('Lateryx: API error', error);
            return null;
        }
    }
}

// Initialize content script
new LaterxyContentScript();
