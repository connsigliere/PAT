"""
Authentication and Security Module
Handles user authentication, session management, and API keys
"""

import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass
import bcrypt
from loguru import logger


@dataclass
class User:
    """User data structure"""
    id: int
    username: str
    email: str
    password_hash: str
    api_key: Optional[str]
    is_active: bool
    is_admin: bool
    created_at: str
    last_login: Optional[str]


@dataclass
class Session:
    """Session data structure"""
    session_id: str
    user_id: int
    created_at: str
    expires_at: str
    ip_address: str
    user_agent: str


class AuthManager:
    """Manage authentication and authorization"""

    def __init__(self, db_path: str = "./auth.db"):
        """
        Initialize auth manager

        Args:
            db_path: Path to authentication database
        """
        self.db_path = Path(db_path)
        self._init_database()

    def _init_database(self):
        """Initialize authentication database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_key TEXT UNIQUE,
                is_active BOOLEAN DEFAULT 1,
                is_admin BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # Login attempts table (for rate limiting)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        conn.commit()
        conn.close()

        logger.info("Authentication database initialized")

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False
    ) -> Optional[User]:
        """
        Create a new user

        Args:
            username: Username
            email: Email address
            password: Plain text password
            is_admin: Whether user has admin privileges

        Returns:
            User object or None if creation failed
        """
        try:
            # Hash password
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            # Generate API key
            api_key = self._generate_api_key()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, email, password_hash, api_key, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, password_hash, api_key, is_admin, datetime.now().isoformat()))

            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            logger.info(f"User created: {username}")
            return self.get_user_by_id(user_id)

        except sqlite3.IntegrityError as e:
            logger.error(f"User creation failed: {e}")
            return None

    def authenticate(self, username: str, password: str, ip_address: str = None) -> Optional[User]:
        """
        Authenticate user with username and password

        Args:
            username: Username
            password: Plain text password
            ip_address: Client IP address

        Returns:
            User object if authentication successful, None otherwise
        """
        # Check rate limiting
        if not self._check_rate_limit(username, ip_address):
            logger.warning(f"Rate limit exceeded for {username} from {ip_address}")
            return None

        # Get user
        user = self.get_user_by_username(username)

        # Log attempt
        self._log_login_attempt(username, ip_address, user is not None)

        if not user or not user.is_active:
            return None

        # Verify password
        if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            # Update last login
            self._update_last_login(user.id)

            # Log successful authentication
            self.log_audit(user.id, "login", f"Successful login from {ip_address}", ip_address)

            logger.info(f"User authenticated: {username}")
            return user

        return None

    def create_session(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        duration_hours: int = 24
    ) -> str:
        """
        Create a new session for user

        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            duration_hours: Session duration in hours

        Returns:
            Session ID
        """
        session_id = secrets.token_urlsafe(32)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=duration_hours)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, created_at.isoformat(), expires_at.isoformat(), ip_address, user_agent))

        conn.commit()
        conn.close()

        logger.info(f"Session created for user {user_id}")
        return session_id

    def validate_session(self, session_id: str) -> Optional[User]:
        """
        Validate session and return user

        Args:
            session_id: Session ID

        Returns:
            User object if session valid, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM sessions WHERE session_id = ?
        """, (session_id,))

        session = cursor.fetchone()
        conn.close()

        if not session:
            return None

        # Check expiration
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            self.delete_session(session_id)
            return None

        # Get user
        return self.get_user_by_id(session['user_id'])

    def validate_api_key(self, api_key: str) -> Optional[User]:
        """
        Validate API key and return user

        Args:
            api_key: API key

        Returns:
            User object if API key valid, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM users WHERE api_key = ? AND is_active = 1
        """, (api_key,))

        row = cursor.fetchone()
        conn.close()

        if row:
            return User(**dict(row))

        return None

    def delete_session(self, session_id: str):
        """Delete a session (logout)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

        conn.commit()
        conn.close()

    def delete_expired_sessions(self):
        """Delete all expired sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM sessions WHERE expires_at < ?
        """, (datetime.now().isoformat(),))

        count = cursor.rowcount
        conn.commit()
        conn.close()

        if count > 0:
            logger.info(f"Deleted {count} expired sessions")

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(**dict(row))

        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(**dict(row))

        return None

    def list_users(self) -> list:
        """List all users"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()

        return [User(**dict(row)) for row in rows]

    def update_password(self, user_id: int, new_password: str) -> bool:
        """Update user password"""
        try:
            password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users SET password_hash = ? WHERE id = ?
            """, (password_hash, user_id))

            conn.commit()
            conn.close()

            logger.info(f"Password updated for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Password update failed: {e}")
            return False

    def regenerate_api_key(self, user_id: int) -> Optional[str]:
        """Regenerate API key for user"""
        api_key = self._generate_api_key()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users SET api_key = ? WHERE id = ?
        """, (api_key, user_id))

        conn.commit()
        conn.close()

        logger.info(f"API key regenerated for user {user_id}")
        return api_key

    def log_audit(self, user_id: Optional[int], action: str, details: str = None, ip_address: str = None):
        """Log security audit event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, action, details, ip_address, datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def get_audit_log(self, limit: int = 100) -> list:
        """Get recent audit log entries"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def _generate_api_key(self) -> str:
        """Generate a secure API key"""
        return f"pat_{secrets.token_urlsafe(32)}"

    def _update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users SET last_login = ? WHERE id = ?
        """, (datetime.now().isoformat(), user_id))

        conn.commit()
        conn.close()

    def _log_login_attempt(self, username: str, ip_address: str, success: bool):
        """Log login attempt for rate limiting"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO login_attempts (username, ip_address, success, timestamp)
            VALUES (?, ?, ?, ?)
        """, (username, ip_address, success, datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def _check_rate_limit(self, username: str, ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """
        Check if rate limit exceeded for login attempts

        Args:
            username: Username attempting login
            ip_address: IP address
            max_attempts: Maximum failed attempts allowed
            window_minutes: Time window for rate limiting

        Returns:
            True if within rate limit, False if exceeded
        """
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE (username = ? OR ip_address = ?)
            AND success = 0
            AND timestamp > ?
        """, (username, ip_address, cutoff_time.isoformat()))

        count = cursor.fetchone()[0]
        conn.close()

        return count < max_attempts


if __name__ == "__main__":
    # Example usage and testing
    auth = AuthManager()

    # Create default admin user
    admin = auth.create_user(
        username="admin",
        email="admin@example.com",
        password="Change_This_Password_123!",
        is_admin=True
    )

    if admin:
        print(f"Admin user created: {admin.username}")
        print(f"API Key: {admin.api_key}")
    else:
        print("Admin user already exists")
