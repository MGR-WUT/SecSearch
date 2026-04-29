import subprocess
import json
import tempfile


def run_bandit(code: str) -> dict[list[dict]]:
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(code.encode())
        path = f.name

    result = subprocess.run(
        ["bandit", "-f", "json", path], capture_output=True, text=True
    )

    return json.loads(result.stdout)


def has_issues(bandit_result):
    return len(bandit_result.get("results", [])) > 0


if __name__ == "__main__":
    code = """
import subprocess
import hashlib
import sqlite3

PASSWORD = "admin123"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{{username}}'"
    cursor.execute(query)  # vulnerable

    return cursor.fetchall()

def ping_host(host):
    command = f"ping -c 1 {{host}}"
    subprocess.call(command, shell=True)  # dangerous

def run_user_code(user_input):
    return eval(user_input)


if __name__ == "__main__":
    print(hash_password("test"))
    print(get_user("admin' OR '1'='1"))
    ping_host("127.0.0.1; rm -rf /")
    run_user_code("print('executed')")

"""
    results = run_bandit(code)
    print(results)
