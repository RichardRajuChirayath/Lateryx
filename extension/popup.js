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

        // Setup link button
        const linkBtn = document.getElementById('link-repo-btn');
        if (linkBtn) {
            linkBtn.addEventListener('click', () => this.saveMapping());
        }

        await this.checkCurrentPage();
    }

    async saveMapping() {
        const input = document.getElementById('custom-repo');
        const repoPath = input.value.trim();

        if (!repoPath.includes('/')) {
            alert('Please use owner/repo format (e.g. owner/repo)');
            return;
        }

        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const domain = new URL(tab.url).hostname;

        const data = await chrome.storage.local.get('lateryx_mappings');
        const mappings = data.lateryx_mappings || {};
        mappings[domain] = repoPath;

        await chrome.storage.local.set({ lateryx_mappings: mappings });
        alert(`Linked ${domain} to ${repoPath}`);
        this.refresh();
    }

    async checkCurrentPage() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = tab.url;

            const prMatch = url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);

            if (prMatch) {
                const [, owner, repo, prNumber] = prMatch;
                await this.loadPRStatus(owner, repo, prNumber);
            } else {
                const domain = new URL(url).hostname;
                const data = await chrome.storage.local.get('lateryx_mappings');
                const mappings = data.lateryx_mappings || {};

                if (mappings[domain]) {
                    const [owner, repo] = mappings[domain].split('/');
                    await this.loadGlobalStatus(owner, repo);
                } else if (url.includes('github.com')) {
                    this.showNotPR();
                } else {
                    this.showNotGithub();
                }
            }
        } catch (error) {
            console.error('Error checking page:', error);
            this.showError('Failed to analyze page');
        }
    }

    async loadPRStatus(owner, repo, prNumber) {
        this.showLoading();
        try {
            const checkStatus = await this.getCheckStatus(owner, repo, prNumber);
            document.getElementById('pr-title').textContent = `${owner}/${repo}`;
            document.getElementById('pr-number').textContent = `#${prNumber}`;

            if (checkStatus) {
                this.showPRStatus(checkStatus);
            } else {
                this.showNoLateryx();
            }
        } catch (error) {
            this.showError('Could not load PR status');
        }
    }

    async loadGlobalStatus(owner, repo) {
        this.showLoading();
        try {
            const checkStatus = await this.getLatestCheckStatus(owner, repo);
            document.getElementById('pr-title').textContent = `${owner}/${repo}`;
            document.getElementById('pr-number').textContent = `Main Branch`;

            if (checkStatus) {
                this.showPRStatus(checkStatus);
            } else {
                this.showNoLateryx();
            }
        } catch (error) {
            this.showError('Could not load repo status');
        }
    }

    async getCheckStatus(owner, repo, prNumber) {
        try {
            const prResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`, { headers: this.getHeaders() });
            if (!prResponse.ok) return null;
            const prData = await prResponse.json();
            const headSha = prData.head.sha;

            const checksResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${headSha}/check-runs`, { headers: this.getHeaders() });
            if (!checksResponse.ok) return null;
            const checksData = await checksResponse.json();

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
        } catch (error) { return null; }
    }

    async getLatestCheckStatus(owner, repo) {
        try {
            const checksResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/main/check-runs`, { headers: this.getHeaders() });
            if (!checksResponse.ok) return null;
            const checksData = await checksResponse.json();

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
        } catch (error) { return null; }
    }

    getHeaders() {
        return { 'Accept': 'application/vnd.github.v3+json' };
    }

    parseFindings(output) {
        if (!output || !output.text) {
            return { total: 0, critical: 0, high: 0, items: [] };
        }

        const text = output.text;
        const findings = { total: 0, critical: 0, high: 0, items: [] };

        const breachMatch = text.match(/Breaches Detected[:\s]+(\d+)/i);
        if (breachMatch) findings.total = parseInt(breachMatch[1], 10);

        const criticalMatch = text.match(/CRITICAL[:\s]+(\d+)/i);
        if (criticalMatch) findings.critical = parseInt(criticalMatch[1], 10);

        const highMatch = text.match(/HIGH[:\s]+(\d+)/i);
        if (highMatch) findings.high = parseInt(highMatch[1], 10);

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
        this.statusIndicator.className = `status-indicator ${isSafe ? 'safe' : 'unsafe'}`;
        this.statusIndicator.innerHTML = `
            <div class="status-icon">${isSafe ? '✅' : '⚠️'}</div>
            <div class="status-text">
                <h2>${isSafe ? 'Safe to Ship' : 'Security Issues Found'}</h2>
                <p>${isSafe ? 'No causality breaches detected' : `${checkStatus.findings.total} issues need attention`}</p>
            </div>
        `;

        document.getElementById('metric-findings').textContent = checkStatus.findings.total;
        document.getElementById('metric-critical').textContent = checkStatus.findings.critical;

        const complianceScore = checkStatus.findings.total === 0 ? 100 :
            Math.max(0, 100 - (checkStatus.findings.critical * 20) - (checkStatus.findings.high * 10));
        document.getElementById('metric-compliance').textContent = `${complianceScore}%`;

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

document.addEventListener('DOMContentLoaded', () => {
    new LaterxyPopup();
});
