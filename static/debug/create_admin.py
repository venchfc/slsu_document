"""Create an initial admin account for local development.

Usage:
    c:/Users/HYPERLINK/Music/slsu_document/.venv/Scripts/python.exe static/debug/create_admin.py
"""

from pathlib import Path
import sqlite3
import sys

from werkzeug.security import generate_password_hash

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db import DATABASE_PATH, init_db  # noqa: E402


def _get_role_id(connection: sqlite3.Connection, role_name: str) -> int:
    row = connection.execute('SELECT id FROM roles WHERE name = ?;', (role_name,)).fetchone()
    if not row:
        raise RuntimeError(f'Missing role: {role_name}')
    return int(row[0])


def main() -> None:
    init_db()

    email = input('Admin email: ').strip().lower()
    first_name = input('First name: ').strip()
    last_name = input('Last name: ').strip()
    password = input('Password: ').strip()

    if not email or not first_name or not last_name or len(password) < 8:
        print('Invalid input. Password must be at least 8 characters.')
        return

    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute('PRAGMA foreign_keys = ON;')

    existing = connection.execute('SELECT id FROM users WHERE email = ?;', (email,)).fetchone()
    if existing:
        print('Admin user already exists for this email.')
        connection.close()
        return

    cursor = connection.execute(
        """
        INSERT INTO users(email, password_hash, first_name, last_name)
        VALUES (?, ?, ?, ?);
        """,
        (email, generate_password_hash(password), first_name, last_name),
    )
    user_id = int(cursor.lastrowid)

    admin_role_id = _get_role_id(connection, 'admin')
    connection.execute(
        'INSERT INTO user_roles(user_id, role_id) VALUES (?, ?);',
        (user_id, admin_role_id),
    )

    connection.commit()
    connection.close()
    print('Admin account created successfully.')


if __name__ == '__main__':
    main()
