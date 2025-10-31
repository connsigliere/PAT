# Contributing to Phishing Infrastructure Automation Tool

Thank you for your interest in contributing! This project is designed for **authorized penetration testing only**.

## Code of Conduct

By participating in this project, you agree to:
- Use the tool only for lawful, authorized purposes
- Not contribute features designed to circumvent authorization checks
- Follow ethical security research practices
- Respect all applicable laws and regulations

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version, etc.)

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Clearly describe the feature and its use case
3. Explain why it would be valuable for authorized testing
4. Include examples if applicable

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Standards

- Follow PEP 8 style guidelines
- Include docstrings for all functions and classes
- Add type hints where appropriate
- Keep functions focused and modular
- Write clear commit messages

### Testing

- Test your changes thoroughly
- Include unit tests for new features
- Ensure existing tests still pass
- Test on multiple environments if possible

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/phishing-automation-tool.git
cd phishing-automation-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8

# Run tests
pytest

# Format code
black src/

# Lint code
flake8 src/
```

## What We're Looking For

**High Priority:**
- Bug fixes
- Documentation improvements
- Additional email templates
- Better evasion techniques
- Enhanced reporting features
- Performance improvements

**Medium Priority:**
- New authentication methods
- API integrations
- Dashboard/UI improvements
- Additional language support

**Please Do NOT Contribute:**
- Features that bypass authorization checks
- Exploits or vulnerabilities in third-party systems
- Techniques designed solely for malicious use
- Anything that violates ethical guidelines

## Security

If you discover a security vulnerability in this tool, please:
1. **DO NOT** open a public issue
2. Email the maintainers privately
3. Provide details on the vulnerability
4. Give reasonable time for a fix before public disclosure

## Questions?

Feel free to open an issue with the "question" label or reach out to the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Remember: This tool is for authorized testing only. Contribute responsibly!**
