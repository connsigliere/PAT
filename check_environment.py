#!/usr/bin/env python3
"""
Environment Check Script
Validates Python version and dependencies before running the application
"""

import sys
import subprocess
import platform
from pathlib import Path

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def print_header(text):
    """Print a formatted header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text:^60}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓{RESET} {text}")


def print_error(text):
    """Print error message"""
    print(f"{RED}✗{RESET} {text}")


def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠{RESET} {text}")


def check_python_version():
    """Check if Python version is compatible"""
    print_header("CHECKING PYTHON VERSION")

    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    print(f"Python Version: {version_str}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")

    if version.major == 3 and version.minor == 12:
        print_success(f"Python 3.12 detected - Perfect!")
        return True
    elif version.major == 3 and version.minor >= 9 and version.minor < 13:
        print_warning(f"Python {version_str} detected - Compatible but 3.12 recommended")
        return True
    elif version.major == 3 and version.minor >= 13:
        print_warning(f"Python {version_str} detected - Some libraries may not be available yet")
        print_warning("Python 3.12 is recommended for full compatibility")
        return True
    else:
        print_error(f"Python {version_str} is not supported")
        print_error("Python 3.12 is required (3.9-3.12 supported)")
        return False


def check_pip():
    """Check if pip is available"""
    print_header("CHECKING PIP")

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_success(f"pip is available: {result.stdout.strip()}")
            return True
        else:
            print_error("pip is not working correctly")
            return False
    except Exception as e:
        print_error(f"pip check failed: {e}")
        return False


def check_dependencies():
    """Check if required dependencies are installed"""
    print_header("CHECKING DEPENDENCIES")

    required_packages = [
        'flask',
        'flask_cors',
        'bcrypt',
        'loguru',
        'requests',
        'beautifulsoup4',
        'cryptography',
        'dnspython',
        'sqlalchemy'
    ]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print_success(f"{package:20} - Installed")
        except ImportError:
            print_error(f"{package:20} - Missing")
            missing_packages.append(package)

    if missing_packages:
        print_warning(f"\n{len(missing_packages)} package(s) missing")
        print("Run: pip install -r requirements.txt")
        return False
    else:
        print_success(f"\nAll required packages are installed")
        return True


def check_directories():
    """Check if required directories exist"""
    print_header("CHECKING DIRECTORIES")

    required_dirs = [
        'src',
        'src/core',
        'src/api',
        'src/web',
        'src/web/templates',
        'src/web/static',
        'config',
        'logs'
    ]

    all_exist = True

    for directory in required_dirs:
        dir_path = Path(directory)
        if dir_path.exists():
            print_success(f"{directory:30} - Exists")
        else:
            print_error(f"{directory:30} - Missing")
            all_exist = False

    return all_exist


def check_configuration():
    """Check if configuration files exist"""
    print_header("CHECKING CONFIGURATION")

    config_file = Path('config/config.example.yml')
    if config_file.exists():
        print_success("config.example.yml - Found")
    else:
        print_warning("config.example.yml - Missing (optional)")

    user_config = Path('config/config.yml')
    if user_config.exists():
        print_success("config.yml - Found")
    else:
        print_warning("config.yml - Not configured (will use defaults)")

    return True


def check_security_setup():
    """Check if security has been configured"""
    print_header("CHECKING SECURITY SETUP")

    auth_db = Path('auth.db')
    env_file = Path('.env')

    if auth_db.exists():
        print_success("auth.db - Security database exists")
        security_configured = True
    else:
        print_warning("auth.db - Not configured")
        print("         Run: python setup_security.py")
        security_configured = False

    if env_file.exists():
        print_success(".env - Environment variables configured")
    else:
        print_warning(".env - Not configured")

    return security_configured


def test_import_modules():
    """Test importing main application modules"""
    print_header("TESTING MODULE IMPORTS")

    modules_to_test = [
        ('src.core.domain_checker', 'Domain Checker'),
        ('src.core.email_generator', 'Email Generator'),
        ('src.core.page_cloner', 'Page Cloner'),
        ('src.core.campaign_manager', 'Campaign Manager'),
        ('src.core.auth', 'Authentication'),
        ('src.api.security', 'Security Middleware'),
    ]

    all_success = True

    # Add src to path
    src_path = Path(__file__).parent / 'src'
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path.parent))

    for module_name, display_name in modules_to_test:
        try:
            __import__(module_name)
            print_success(f"{display_name:25} - OK")
        except Exception as e:
            print_error(f"{display_name:25} - Failed: {str(e)[:50]}")
            all_success = False

    return all_success


def print_summary(checks):
    """Print summary of all checks"""
    print_header("ENVIRONMENT CHECK SUMMARY")

    total = len(checks)
    passed = sum(checks.values())

    for check_name, result in checks.items():
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"{check_name:30} [{status}]")

    print(f"\n{passed}/{total} checks passed")

    if passed == total:
        print_success("\n✓ Environment is ready!")
        print("\nYou can now run:")
        print("  - python start_web.py           (without authentication)")
        print("  - python start_web_secure.py    (with authentication)")
        return True
    else:
        print_error("\n✗ Environment has issues that need to be fixed")
        return False


def main():
    """Run all environment checks"""
    print(f"""
{BLUE}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Phishing Automation Tool - Environment Check                ║
║   Validating Python 3.12 Compatibility                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{RESET}
    """)

    checks = {
        'Python Version': check_python_version(),
        'Pip Installation': check_pip(),
        'Dependencies': check_dependencies(),
        'Directory Structure': check_directories(),
        'Configuration': check_configuration(),
        'Security Setup': check_security_setup(),
        'Module Imports': test_import_modules()
    }

    result = print_summary(checks)

    # Additional recommendations
    print_header("RECOMMENDATIONS")

    if not checks['Dependencies']:
        print("1. Install dependencies:")
        print("   pip install -r requirements.txt")

    if not checks['Security Setup']:
        print("2. Configure security:")
        print("   python setup_security.py")

    if not Path('config/config.yml').exists():
        print("3. Configure application:")
        print("   cp config/config.example.yml config/config.yml")
        print("   # Edit config.yml with your settings")

    print("\n4. For production deployment, see DEPLOYMENT_GUIDE.md")

    return 0 if result else 1


if __name__ == '__main__':
    sys.exit(main())
