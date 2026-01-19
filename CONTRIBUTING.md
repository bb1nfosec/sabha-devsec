# Contributing to SABHA-DevSec

Thank you for your interest in contributing! 🎉

## Quick Start

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/amazing-feature`
3. **Make changes** and test locally
4. **Test**: `python -m http.server 8000` → Open `http://localhost:8000`
5. **Commit**: `git commit -m 'Add: amazing feature'`
6. **Push**: `git push origin feature/amazing-feature`
7. **Open Pull Request**

## Development Guidelines

- ✅ **No build process** - This is vanilla JavaScript (edit and refresh!)
- ✅ **Privacy-first** - All processing must be client-side only
- ✅ **Zero dependencies** - Use CDN-loaded libraries only (React, Recharts, PapaParse)
- ✅ **Code style** - Follow existing patterns in `app-nojs.js`
- ✅ **Documentation** - Update README.md for new features

## Adding New Security Tool Support

To add support for a new security scanner:

### 1. **Add Parser Function** (`app-nojs.js`)
```javascript
static parseYourToolXML(xmlDoc, source) {
    const findings = [];
    // Parse tool-specific XML structure
    return findings;
}
```

### 2. **Update Auto-Detection** (`extractFindingsFromXML`)
Add detection logic for your tool's XML structure

### 3. **Create Sample Data** (`sample-data/`)
Add a sample export file: `yourtool-scan.xml`

### 4. **Document Export Process** (`TOOL-SUPPORT.md`)
Add instructions on how to export from your tool

### 5. **Test Thoroughly**
- Test with multiple real scan outputs
- Verify all severity levels map correctly
- Check financial impact calculations

## Bug Reports

Please include:
- **Browser version** (Chrome 120, Firefox 115, etc.)
- **Steps to reproduce** (1, 2, 3...)
- **Sample scan file** (anonymized - remove real IPs, domains)
- **Expected behavior** vs **Actual behavior**
- **Screenshots** (if applicable)

**Template**:
```markdown
## Bug Description
[Clear description]

## Steps to Reproduce
1. Upload file: [file type]
2. Click: [action]
3. See error: [description]

## Expected
[What should happen]

## Actual
[What actually happens]

## Environment
- Browser: [name and version]
- OS: [Windows/Mac/Linux]
```

## Feature Requests

Open an issue with:
- **Use case**: Why is this needed?
- **Proposed solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Impact**: Who benefits from this?

## Pull Request Guidelines

### Before Submitting:
- [ ] Code follows existing style
- [ ] Tested in 2+ browsers
- [ ] Documentation updated
- [ ] No console errors
- [ ] Privacy-first principles maintained

### PR Title Format:
- `Add: [new feature]`
- `Fix: [bug description]`
- `Update: [component/doc name]`
- `Refactor: [what was refactored]`

### PR Description Template:
```markdown
## What does this PR do?
[Description]

## Why is this needed?
[Use case]

## How was it tested?
- [ ] Local testing
- [ ] Multiple browsers
- [ ] Sample data verified

## Screenshots (if UI changes)
[Add screenshots]
```

## Code Review Process

1. **Automated checks** run (linting, etc.)
2. **Maintainer review** (usually within 48 hours)
3. **Feedback addressed** (if any)
4. **Merge** to main branch
5. **Release** in next version

## Questions or Need Help?

- 💬 **Discussions**: https://github.com/bb1nfosec/sabha-devsec/discussions
- 🐛 **Issues**: https://github.com/bb1nfosec/sabha-devsec/issues
- 📧 **Email**: dev@bb1nfosec.com

## Recognition

All contributors will be:
- ✅ Listed in **Contributors** section
- ✅ Mentioned in **Release Notes**
- ✅ Credited in **README.md** (for significant contributions)

## Code of Conduct

Be respectful, inclusive, and professional. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

**We appreciate all contributions, whether it's code, documentation, bug reports, or feature ideas!** ⭐

Thank you for making SABHA-DevSec better! 🛡️
