# Lateryx Browser Extension

A cross-browser extension that shows Lateryx security status directly on GitHub Pull Requests.

## Features

- 🛡️ **Security Status Badge**: See security status at a glance on any GitHub PR
- 📊 **Detailed Popup**: View findings, compliance score, and remediation steps
- ⚡ **Real-time Updates**: Status updates automatically when checks complete
- 🌐 **Cross-Browser**: Works on Chrome, Firefox, Edge, Brave, and Opera

## Installation

### Chrome / Edge / Brave

1. Download the extension folder or clone the repository
2. Open `chrome://extensions` (or `edge://extensions`)
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the `extension` folder from this repository

### Firefox

1. Download the extension folder
2. Open `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select any file in the `extension` folder

### For Production (Chrome Web Store)

Coming soon! The extension will be published to:
- Chrome Web Store
- Firefox Add-ons
- Edge Add-ons

## Usage

1. Navigate to any GitHub Pull Request page
2. Look for the **Lateryx badge** in the PR header
3. Click the badge to see detailed security analysis
4. Click the extension icon in your browser toolbar for full details

### Badge States

| Badge | Meaning |
|-------|---------|
| ✅ **Safe to Ship** | No security issues detected |
| ⚠️ **X Issues** | Security issues found - review needed |
| 🔧 **Add Lateryx** | Lateryx GitHub Action not configured |
| ⏳ **Checking...** | Analysis in progress |

## How It Works

The extension:

1. Detects when you're viewing a GitHub Pull Request
2. Fetches the Lateryx check run status from GitHub's API
3. Displays a badge directly in the PR header
4. Shows detailed findings in the popup

**Note**: This extension reads publicly available GitHub check run data. For private repositories, you may need to authenticate with a GitHub Personal Access Token.

## Configuration

Click the extension icon and access Settings to configure:

- **GitHub Token**: For private repository access (optional)
- **Auto-inject badges**: Enable/disable automatic badge injection

## Privacy

- ❌ No data collection
- ❌ No tracking
- ❌ No external servers
- ✅ All API calls go directly to GitHub
- ✅ Settings stored locally in your browser

## Development

```bash
# Clone the repository
git clone https://github.com/RichardRajuChirayath/Lateryx.git
cd Lateryx/extension

# Make changes to the code

# Load in Chrome for testing
# 1. Open chrome://extensions
# 2. Enable Developer Mode
# 3. Load unpacked → select this folder
```

### File Structure

```
extension/
├── manifest.json      # Extension configuration
├── popup.html         # Popup UI
├── popup.css          # Popup styles
├── popup.js           # Popup logic
├── content.js         # GitHub page integration
├── content.css        # Injected styles
├── background.js      # Service worker
└── icons/             # Extension icons
```

## Support

- [GitHub Issues](https://github.com/RichardRajuChirayath/Lateryx/issues)
- [Documentation](https://richardrajuchirayath.github.io/Lateryx/documentation.html)

## License

AGPL-3.0 - See [LICENSE](../LICENSE)
