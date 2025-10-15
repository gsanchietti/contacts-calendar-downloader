"""PostgreSQL database backend for the application."""

import os
import json
import pickle
import hashlib
from typing import Any, Dict, List, Optional
from datetime import datetime
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor


class DatabaseBackend:
    """PostgreSQL database backend."""
    
    def __init__(self, config: Any):
        """Initialize PostgreSQL backend with configuration."""
        self.config = config
        
        # Get PostgreSQL connection parameters from environment
        self.connection_params = {
            'host': os.environ.get('POSTGRES_HOST', '127.0.0.1'),
            'port': int(os.environ.get('POSTGRES_PORT', '5432')),
            'database': os.environ.get('POSTGRES_DB', 'downloader'),
            'user': os.environ.get('POSTGRES_USER', 'downloader'),
            'password': os.environ.get('POSTGRES_PASSWORD', 'changeme'),
        }
        
        # Create connection pool for better performance
        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=20,
                **self.connection_params
            )
        except Exception as e:
            print(f"Failed to create PostgreSQL connection pool: {e}")
            print("Please ensure PostgreSQL is running and credentials are correct")
            raise
    
    def init_database(self) -> None:
        """Initialize PostgreSQL database with required tables."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Create table for OAuth tokens (support multiple providers)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_tokens (
                        user_email TEXT,
                        provider TEXT DEFAULT 'google',
                        user_hash TEXT NOT NULL,
                        token_data BYTEA NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (user_email, provider)
                    )
                ''')
                
                # Create table for access tokens (support multiple providers)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS access_tokens (
                        access_token BYTEA,
                        provider TEXT DEFAULT 'google',
                        user_email TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (access_token, provider),
                        FOREIGN KEY (user_email, provider) REFERENCES user_tokens (user_email, provider) ON DELETE CASCADE
                    )
                ''')
                
                # Create table for OAuth flows (supporting provider identification)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS oauth_flows (
                        state TEXT PRIMARY KEY,
                        provider TEXT DEFAULT 'google',
                        credentials_path TEXT NOT NULL,
                        scopes TEXT NOT NULL,
                        redirect_uri TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create index for faster lookups
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_access_tokens_user_email 
                    ON access_tokens (user_email)
                ''')
                
                # Create index for OAuth flows cleanup
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_oauth_flows_created_at 
                    ON oauth_flows (created_at)
                ''')
                
                # Create table for permanent export tokens
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS export_tokens (
                        export_token TEXT PRIMARY KEY,
                        user_email TEXT NOT NULL,
                        provider TEXT DEFAULT 'google',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_email, provider) REFERENCES user_tokens (user_email, provider) ON DELETE CASCADE
                    )
                ''')
                
                # Create index for export tokens
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_export_tokens_user_email 
                    ON export_tokens (user_email, provider)
                ''')
                
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def get_connection(self):
        """Get a connection from the pool."""
        return self.pool.getconn()
    
    def return_connection(self, conn) -> None:
        """Return a connection to the pool."""
        self.pool.putconn(conn)
    
    def close(self) -> None:
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using the encryption cipher."""
        from cryptography.fernet import Fernet
        encryption_key = os.environ.get('ENCRYPTION_KEY', 'secret')
        if len(encryption_key) != 44:
            # Generate a proper key from the secret
            import base64
            key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32].encode())
        else:
            key = encryption_key.encode()
        cipher = Fernet(key)
        return cipher.encrypt(data)
    
    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the encryption cipher."""
        from cryptography.fernet import Fernet
        encryption_key = os.environ.get('ENCRYPTION_KEY', 'secret')
        if len(encryption_key) != 44:
            # Generate a proper key from the secret
            import base64
            key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32].encode())
        else:
            key = encryption_key.encode()
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data)
    
    def save_user_credentials(self, user_email: str, credentials: Any, provider: str = 'google') -> None:
        """Save user OAuth credentials with encryption."""
        user_hash = hashlib.sha256(user_email.encode()).hexdigest()[:16]
        token_data = pickle.dumps(credentials)
        encrypted_token_data = self._encrypt_data(token_data)
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO user_tokens (user_email, provider, user_hash, token_data) 
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (user_email, provider) 
                       DO UPDATE SET user_hash = EXCLUDED.user_hash, 
                                     token_data = EXCLUDED.token_data,
                                     updated_at = CURRENT_TIMESTAMP""",
                    (user_email, provider, user_hash, psycopg2.Binary(encrypted_token_data))
                )
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def load_user_credentials(self, user_email: str, provider: str = 'google') -> Optional[Any]:
        """Load user OAuth credentials with decryption."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT token_data FROM user_tokens WHERE user_email = %s AND provider = %s",
                    (user_email, provider)
                )
                row = cursor.fetchone()
                if row:
                    try:
                        decrypted_token_data = self._decrypt_data(bytes(row["token_data"]))
                        return pickle.loads(decrypted_token_data)
                    except Exception:
                        return None
                return None
        finally:
            self.return_connection(conn)
    
    def get_user_provider(self, user_email: str) -> str:
        """Get the provider for a user, default to 'google'."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT provider FROM user_tokens WHERE user_email = %s LIMIT 1", (user_email,))
                row = cursor.fetchone()
                if row and row[0]:
                    return row[0]
            return 'google'
        finally:
            self.return_connection(conn)
    
    def create_access_token(self, access_token: str, user_email: str, provider: str = 'google') -> None:
        """Create an encrypted access token."""
        encrypted_token = self._encrypt_data(access_token.encode())
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO access_tokens (access_token, provider, user_email) 
                       VALUES (%s, %s, %s)
                       ON CONFLICT (access_token, provider) 
                       DO UPDATE SET user_email = EXCLUDED.user_email""",
                    (psycopg2.Binary(encrypted_token), provider, user_email)
                )
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def get_user_from_token(self, token: str, provider: Optional[str] = None) -> Optional[str]:
        """Get user email from access token."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                if provider:
                    cursor.execute(
                        "SELECT access_token, user_email FROM access_tokens WHERE provider = %s",
                        (provider,)
                    )
                else:
                    cursor.execute("SELECT access_token, user_email FROM access_tokens")
                rows = cursor.fetchall()

                for row in rows:
                    try:
                        decrypted_token = self._decrypt_data(bytes(row["access_token"])).decode()
                        if decrypted_token == token:
                            return row["user_email"]
                    except Exception:
                        continue
                return None
        finally:
            self.return_connection(conn)
    
    def get_provider_from_token(self, token: str) -> Optional[Dict[str, str]]:
        """Get user email and provider from access token."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT access_token, user_email, provider FROM access_tokens")
                rows = cursor.fetchall()

                for row in rows:
                    try:
                        decrypted_token = self._decrypt_data(bytes(row["access_token"])).decode()
                        if decrypted_token == token:
                            return {"user_email": row["user_email"], "provider": row["provider"]}
                    except Exception:
                        continue
                return None
        finally:
            self.return_connection(conn)
    
    def revoke_access_token(self, token: str, provider: str = 'google') -> bool:
        """Revoke an access token."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                if provider:
                    cursor.execute(
                        "SELECT access_token, user_email FROM access_tokens WHERE provider = %s",
                        (provider,)
                    )
                else:
                    cursor.execute("SELECT access_token, user_email FROM access_tokens")
                rows = cursor.fetchall()

                for row in rows:
                    try:
                        decrypted_token = self._decrypt_data(bytes(row["access_token"])).decode()
                        if decrypted_token == token:
                            # Delete user tokens and access token
                            cursor.execute("DELETE FROM user_tokens WHERE user_email = %s AND provider = %s", 
                                         (row["user_email"], provider))
                            encrypted_token = self._encrypt_data(token.encode())
                            cursor.execute("DELETE FROM access_tokens WHERE access_token = %s", 
                                         (psycopg2.Binary(encrypted_token),))
                            conn.commit()
                            return True
                    except Exception:
                        continue
                return False
        finally:
            self.return_connection(conn)
    
    def list_user_tokens(self, user_email: str, provider: str = 'google') -> List[str]:
        """List all active tokens for a user."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT access_token FROM access_tokens WHERE user_email = %s AND provider = %s",
                    (user_email, provider)
                )
                rows = cursor.fetchall()
                
                user_tokens = []
                for row in rows:
                    try:
                        decrypted_token = self._decrypt_data(bytes(row["access_token"])).decode()
                        user_tokens.append(decrypted_token)
                    except Exception:
                        continue
                return user_tokens
        finally:
            self.return_connection(conn)
    
    def store_oauth_flow(self, state: str, flow_info: Dict[str, Any]) -> None:
        """Store OAuth flow configuration."""
        provider = flow_info.get('provider', 'google')
        scopes_json = json.dumps(flow_info.get('scopes', []))
        credentials_path = flow_info.get('credentials_path', '')
        redirect_uri = flow_info.get('redirect_uri', '')

        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Clean up expired flows (older than 10 minutes)
                cursor.execute(
                    "DELETE FROM oauth_flows WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '10 minutes'"
                )
                # Store new flow
                cursor.execute(
                    """INSERT INTO oauth_flows (state, provider, credentials_path, scopes, redirect_uri) 
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (state) 
                       DO UPDATE SET provider = EXCLUDED.provider, 
                                     credentials_path = EXCLUDED.credentials_path,
                                     scopes = EXCLUDED.scopes,
                                     redirect_uri = EXCLUDED.redirect_uri""",
                    (state, provider, credentials_path, scopes_json, redirect_uri)
                )
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def get_oauth_flow_row(self, state: str) -> Optional[Dict[str, Any]]:
        """Get OAuth flow row for a state."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """SELECT state, provider, credentials_path, scopes, redirect_uri 
                       FROM oauth_flows 
                       WHERE state = %s AND created_at > CURRENT_TIMESTAMP - INTERVAL '10 minutes'""",
                    (state,)
                )
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        finally:
            self.return_connection(conn)
    
    def delete_oauth_flow(self, state: str) -> None:
        """Delete OAuth flow."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM oauth_flows WHERE state = %s", (state,))
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def save_export_token(self, export_token: str, user_email: str, provider: str = 'google') -> None:
        """Save export token."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO export_tokens (export_token, user_email, provider) 
                       VALUES (%s, %s, %s)
                       ON CONFLICT (export_token) DO NOTHING""",
                    (export_token, user_email, provider)
                )
                conn.commit()
        finally:
            self.return_connection(conn)
    
    def get_export_token(self, user_email: str, provider: str = 'google') -> Optional[str]:
        """Get existing export token for user."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT export_token FROM export_tokens WHERE user_email = %s AND provider = %s",
                    (user_email, provider)
                )
                row = cursor.fetchone()
                if row:
                    return row["export_token"]
                return None
        finally:
            self.return_connection(conn)
    
    def get_user_from_export_token(self, export_token: str) -> Optional[Dict[str, str]]:
        """Get user email and provider from export token."""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT user_email, provider FROM export_tokens WHERE export_token = %s",
                    (export_token,)
                )
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        finally:
            self.return_connection(conn)
    
    def revoke_export_token(self, export_token: str) -> bool:
        """Revoke export token."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM export_tokens WHERE export_token = %s", (export_token,))
                rowcount = cursor.rowcount
                conn.commit()
                return rowcount > 0
        finally:
            self.return_connection(conn)
    
    def get_user_count(self) -> int:
        """Get total number of registered users."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM user_tokens")
                return cursor.fetchone()[0]
        finally:
            self.return_connection(conn)
    
    def get_active_token_count(self) -> int:
        """Get number of active access tokens."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM access_tokens")
                return cursor.fetchone()[0]
        finally:
            self.return_connection(conn)
    
    def get_database_size(self) -> int:
        """Get database size in bytes."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_database_size(%s)",
                    (self.connection_params['database'],)
                )
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception:
            return 0
        finally:
            self.return_connection(conn)


# Global database instance
_db_instance = None


def get_db(config=None):
    """Get the global database instance."""
    global _db_instance
    if _db_instance is None:
        if config is None:
            from dataclasses import dataclass
            from pathlib import Path
            # Create a minimal config for initialization
            @dataclass
            class MinimalConfig:
                pass
            config = MinimalConfig()
        _db_instance = DatabaseBackend(config)
    return _db_instance
