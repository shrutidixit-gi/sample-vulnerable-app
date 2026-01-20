# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # FIX: Import ast for safe literal evaluation
import logging

# Configure logging with appropriate security level (do not log sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# hardcoded API token (Issue 1)
# FIX: Sensitive credential should be loaded from environment variables or secure vault, not hardcoded
API_TOKEN = os.getenv("API_TOKEN", "")  # Load from environment; empty string if not set
if not API_TOKEN:
    logger.warning("API_TOKEN not configured. Set the API_TOKEN environment variable.")

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # FIX: Use parameterized query to prevent SQL injection (CWE-89)
    # Parameterized queries separate SQL logic from data, preventing malicious input from altering query structure
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # FIX: Use parameterized query to prevent SQL injection (CWE-89)
    # The placeholder (?) ensures user input is treated as data, not executable SQL code
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # FIX: Replaced insecure pickle.loads() with safe ast.literal_eval()
    # This prevents arbitrary code execution from untrusted input
    # Only safe Python literals (strings, numbers, tuples, lists, dicts, booleans, None) can be evaluated
    try:
        return ast.literal_eval(blob.decode('utf-8') if isinstance(blob, bytes) else blob)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Invalid input: cannot safely deserialize - {e}")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # FIX: Removed direct print of API_TOKEN to prevent sensitive information leak (CWE-200)
    # Instead, log a safe message indicating the token is in use without exposing its value
    logger.info("API_TOKEN configured and in use")
    
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        # FIX: Log error without exposing sensitive details
        logger.error("Deserialization error: %s", str(e))
