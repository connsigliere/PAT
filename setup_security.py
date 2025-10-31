#!/usr/bin/env python3
"""
Security Setup Script
Creates initial admin user and configures security settings
"""

import sys
import os
import secrets
from pathlib import Path
from getpass import getpass

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from core.auth import AuthManager
from loguru import logger


def generate_secret_key():
    """Generate a secure secret key"""
    return secrets.token_hex(32)


def create_admin_user(auth: AuthManager):
    """Interactive admin user creation"""
    print("\n" + "="*60)
    print("CREATE ADMIN USER")
    print("="*60 + "\n")

    while True:
        username = input("Admin Username: ").strip()
        if username:
            break
        print("Username cannot be empty!")

    while True:
        email = input("Admin Email: ").strip()
        if email and '@' in email:
            break
        print("Please enter a valid email address!")

    while True:
        password = getpass("Admin Password (min 12 chars): ")
        if len(password) < 12:
            print("Password must be at least 12 characters!")
            continue

        confirm = getpass("Confirm Password: ")
        if password == confirm:
            break
        print("Passwords do not match!")

    # Create user
    user = auth.create_user(
        username=username,
        email=email,
        password=password,
        is_admin=True
    )

    if user:
        print(f"\n✓ Admin user created successfully!")
        print(f"  Username: {user.username}")
        print(f"  Email: {user.email}")
        print(f"  API Key: {user.api_key}")
        print(f"\n  IMPORTANT: Save your API key - it won't be shown again!")
        return user
    else:
        print("\n✗ Failed to create admin user!")
        print("  User may already exist.")
        return None


def main():
    """Main setup function"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Phishing Automation Tool - Security Setup                   ║
║   Initialize Authentication & Security Features               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    # Initialize auth manager
    auth = AuthManager()

    # Check if admin user already exists
    existing_users = auth.list_users()

    if existing_users:
        print(f"\n⚠  Warning: {len(existing_users)} user(s) already exist in the database.")
        print("\nExisting users:")
        for user in existing_users:
            print(f"  - {user.username} ({user.email}) {'[ADMIN]' if user.is_admin else ''}")

        print("\nOptions:")
        print("  1. Create additional user")
        print("  2. Exit")

        choice = input("\nSelect option (1-2): ").strip()

        if choice == "1":
            is_admin = input("Grant admin privileges? (y/N): ").strip().lower() == 'y'

            print()
            username = input("Username: ").strip()
            email = input("Email: ").strip()
            password = getpass("Password (min 12 chars): ")

            user = auth.create_user(username, email, password, is_admin)
            if user:
                print(f"\n✓ User created: {user.username}")
                print(f"  API Key: {user.api_key}")
        else:
            print("\nExiting...")
            return

    else:
        # Create initial admin user
        user = create_admin_user(auth)

        if not user:
            print("\nSetup failed! Please try again.")
            sys.exit(1)

    # Generate Flask secret key
    print("\n" + "="*60)
    print("FLASK SECRET KEY")
    print("="*60 + "\n")

    secret_key = generate_secret_key()
    print("Generated Flask Secret Key:")
    print(f"\n  {secret_key}\n")

    # Save to .env file
    env_file = Path(".env")
    env_file.write_text(f"FLASK_SECRET_KEY={secret_key}\n")
    print(f"✓ Secret key saved to {env_file}")

    # Security recommendations
    print("\n" + "="*60)
    print("SECURITY RECOMMENDATIONS")
    print("="*60 + "\n")

    print("1. Change default passwords immediately")
    print("2. Use HTTPS in production (never HTTP)")
    print("3. Keep API keys secret and rotate regularly")
    print("4. Enable firewall and restrict access by IP")
    print("5. Monitor audit logs regularly")
    print("6. Keep software dependencies updated")
    print("7. Use strong, unique passwords (12+ characters)")
    print("8. Enable two-factor authentication if possible")
    print("9. Regular security audits and backups")
    print("10. Never expose this tool to the public internet without proper security")

    print("\n" + "="*60)
    print("NEXT STEPS")
    print("="*60 + "\n")

    print("1. Start the secure web server:")
    print("   python start_web_secure.py")
    print()
    print("2. Access the login page:")
    print("   http://localhost:5000/login")
    print()
    print("3. Login with your admin credentials")
    print()
    print("4. Change your password after first login")
    print()
    print("5. Review the SECURITY_GUIDE.md for best practices")

    print("\n" + "="*60)
    print("SETUP COMPLETE!")
    print("="*60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        logger.exception("Setup error")
        sys.exit(1)
