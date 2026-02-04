/**
 * Lateryx Browser Extension - Popup Script
 * Handles UI interactions and GitHub API communication
 */

class LaterxyPopup {
    constructor() {
        this.statusSection = document.getElementById('status-section');
        this.statusIndicator = document.getElementById('status-indicator');
        this.prSection = document.getElementById('pr-section');
        this.notGithubSection = document.getElementById('not-github-section');
        this.refreshBtn = document.getElementById('refresh-btn');

        this.init();
    }

    async init() {
        this.refreshBtn.addEventListener('click', () => this.refresh());
        await this.checkCurrentPage();
    }

    async checkCurrentPage() {
        try {
            // Get current tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = tab.url;

            // Check if on GitHub PR page
            const prMatch = url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);

            if (prMatch) {
                const [, owner, repo, prNumber] = prMatch;
                await this.loadPRStatus(owner, repo, prNumber, tab.id);
            } else if (url.includes('github.com')) {
                this.showNotPR();
            } else {
                this.showNotGithub();
            }
        } catch (error) {
            console.error('Error checking page:', error);
            this.showError('Failed to analyze page');
        }
    }

    async loadPRStatus(owner, repo, prNumber, tabId) {
        this.showLoading();

        try {
            // Try to get Lateryx check status from GitHub
            const checkStatus = await this.getCheckStatus(owner, repo, prNumber);

            // Update UI with PR info
            document.getElementById('pr-title').textContent = `${owner}/${repo}`;
            document.getElementById('pr-number').textContent = `#${prNumber}`;

            if (checkStatus) {
                this.showPRStatus(checkStatus);
            } else {
                // No Lateryx check found - show setup prompt
                this.showNoLateryx();
            }
        } catch (error) {
            console.error('Error loading PR status:', error);
            this.showError('Could not load PR status');
        }
    }

    async getCheckStatus(owner, repo, prNumber) {
        try {
            // Get PR head SHA
            const prResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`,
                { headers: this.getHeaders() }
            );

            if (!prResponse.ok) return null;

            const prData = await prResponse.json();
            const headSha = prData.head.sha;

            // Get check runs for this commit
            const checksResponse = await fetch(
                `https://api.github.com/repos/${owner}/${repo}/commits/${headSha}/check-runs`,
                { headers: this.getHeaders() }
            );

            if (!checksResponse.ok) return null;

            const checksData = await checksResponse.json();

            // Find Lateryx check
            const laterxyCheck = checksData.check_runs.find(check =>
                check.name.toLowerCase().includes('lateryx') ||
                check.name.toLowerCase().includes('security')
            );

            if (!laterxyCheck) return null;

            return {
                status: laterxyCheck.conclusion || laterxyCheck.status,
                findings: this.parseFindings(laterxyCheck.output),
                url: laterxyCheck.html_url
            };
        } catch (error) {
            console.error('API Error:', error);
            return null;
        }
    }

    getHeaders() {
        // Check for stored GitHub token
        return {
            'Accept': 'application/vnd.github.v3+json'
        };
    }

    parseFindings(output) {
        // Parse Lateryx output from check run
        if (!output || !output.text) {
            return { total: 0, critical: 0, high: 0, items: [] };
        }

        const text = output.text;
        const findings = { total: 0, critical: 0, high: 0, items: [] };

        // Parse breach counts from output
        const breachMatch = text.match(/Breaches Detected[:\s]+(\d+)/i);
        if (breachMatch) {
            findings.total = parseInt(breachMatch[1], 10);
        }

        const criticalMatch = text.match(/CRITICAL[:\s]+(\d+)/i);
        if (criticalMatch) {
            findings.critical = parseInt(criticalMatch[1], 10);
        }

        const highMatch = text.match(/HIGH[:\s]+(\d+)/i);
        if (highMatch) {
            findings.high = parseInt(highMatch[1], 10);
        }

        // Extract individual findings
        const findingMatches = text.matchAll(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.+?)(?=\n|$)/gi);
        for (const match of findingMatches) {
            findings.items.push({
                severity: match[1].toUpperCase(),
                description: match[2].trim()
            });
        }

        return findings;
    }

    showPRStatus(checkStatus) {
        const isSafe = checkStatus.status === 'success' || checkStatus.findings.total === 0;

        // Update status indicator
        this.statusIndicator.className = `status-indicator ${isSafe ? 'safe' : 'unsafe'}`;
        this.statusIndicator.innerHTML = `
            <div class="status-icon">${isSafe ? '✅' : '⚠️'}</div>
            <div class="status-text">
                <h2>${isSafe ? 'Safe to Ship' : 'Security Issues Found'}</h2>
                <p>${isSafe ? 'No causality breaches detected' : `${checkStatus.findings.total} issues need attention`}</p>
            </div>
        `;

        // Update metrics
        document.getElementById('metric-findings').textContent = checkStatus.findings.total;
        document.getElementById('metric-critical').textContent = checkStatus.findings.critical;

        const complianceScore = checkStatus.findings.total === 0 ? 100 :
            Math.max(0, 100 - (checkStatus.findings.critical * 20) - (checkStatus.findings.high * 10));
        document.getElementById('metric-compliance').textContent = `${complianceScore}%`;

        // Populate findings list
        const findingsList = document.getElementById('findings-list');
        findingsList.innerHTML = '';

        checkStatus.findings.items.slice(0, 5).forEach(finding => {
            const item = document.createElement('div');
            item.className = 'finding-item';
            item.innerHTML = `
                <span class="finding-severity ${finding.severity.toLowerCase()}">${finding.severity}</span>
                <span class="finding-text">${finding.description}</span>
            `;
            findingsList.appendChild(item);
        });

        // Show PR section
        this.prSection.classList.remove('hidden');
        this.notGithubSection.classList.add('hidden');
    }

    showNoLateryx() {
        this.statusIndicator.className = 'status-indicator';
        this.statusIndicator.innerHTML = `
            <div class="status-icon">🔧</div>
            <div class="status-text">
                <h2>Lateryx Not Configured</h2>
                <p>Add Lateryx GitHub Action to this repo</p>
            </div>
        `;

        // Update metrics to show setup needed
        document.getElementById('metric-findings').textContent = '-';
        document.getElementById('metric-critical').textContent = '-';
        document.getElementById('metric-compliance').textContent = '-';

        this.prSection.classList.remove('hidden');
        this.notGithubSection.classList.add('hidden');
    }

    showNotPR() {
        this.statusIndicator.className = 'status-indicator';
        this.statusIndicator.innerHTML = `
            <div class="status-icon">📂</div>
            <div class="status-text">
                <h2>Not a Pull Request</h2>
                <p>Navigate to a PR to see analysis</p>
            </div>
        `;

        this.prSection.classList.add('hidden');
        this.notGithubSection.classList.add('hidden');
    }

    showNotGithub() {
        this.statusIndicator.className = 'status-indicator';
        this.statusIndicator.innerHTML = `
            <div class="status-icon">🌐</div>
            <div class="status-text">
                <h2>Not on GitHub</h2>
                <p>Visit a GitHub repository</p>
            </div>
        `;

        this.prSection.classList.add('hidden');
        this.notGithubSection.classList.remove('hidden');
    }

    showLoading() {
        this.statusIndicator.className = 'status-indicator loading';
        this.statusIndicator.innerHTML = `
            <div class="status-icon">⏳</div>
            <div class="status-text">
                <h2>Analyzing...</h2>
                <p>Fetching security status</p>
            </div>
        `;
    }

    showError(message) {
        this.statusIndicator.className = 'status-indicator';
        this.statusIndicator.innerHTML = `
            <div class="status-icon">❌</div>
            <div class="status-text">
                <h2>Error</h2>
                <p>${message}</p>
            </div>
        `;
    }

    refresh() {
        this.checkCurrentPage();
    }
}

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
    new LaterxyPopup();
});
