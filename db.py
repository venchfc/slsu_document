import os
import sqlite3
from pathlib import Path

from flask import g


BASE_DIR = Path(__file__).resolve().parent


def _resolve_database_path() -> Path:
    db_url = os.environ.get('DATABASE_URL', '').strip()
    if db_url.startswith('sqlite:///'):
        relative_path = db_url.replace('sqlite:///', '', 1)
        return BASE_DIR / relative_path
    return BASE_DIR / 'slsu_documents.db'


DATABASE_PATH = _resolve_database_path()


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    middle_name TEXT,
    last_name TEXT NOT NULL,
    suffix TEXT,
    graduated_program TEXT,
    major TEXT,
    year_graduated TEXT,
    address TEXT,
    profile_completed INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS document_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL DEFAULT 'Certification',
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    price REAL NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    single_request_only INTEGER NOT NULL DEFAULT 0,
    is_ctc_service INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS request_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    display_order INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS document_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_code TEXT NOT NULL UNIQUE,
    requester_user_id INTEGER NOT NULL,
    document_type_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    notes TEXT,
    current_status_id INTEGER NOT NULL,
    processed_by_user_id INTEGER,
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (document_type_id) REFERENCES document_types(id) ON DELETE RESTRICT,
    FOREIGN KEY (current_status_id) REFERENCES request_statuses(id) ON DELETE RESTRICT,
    FOREIGN KEY (processed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS request_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    status_id INTEGER NOT NULL,
    changed_by_user_id INTEGER NOT NULL,
    remarks TEXT,
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES document_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (status_id) REFERENCES request_statuses(id) ON DELETE RESTRICT,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS registration_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    payload_encrypted TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_reset_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS appointment_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_date TEXT NOT NULL UNIQUE,
    total_slots INTEGER NOT NULL DEFAULT 0,
    created_by_user_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS appointment_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference_code TEXT,
    slot_id INTEGER NOT NULL,
    student_user_id INTEGER NOT NULL,
    purpose TEXT,
    status TEXT NOT NULL DEFAULT 'booked',
    ctc_mode TEXT NOT NULL DEFAULT 'none',
    ctc_external_label TEXT,
    claim_date TEXT,
    claim_requirements TEXT,
    progress_note TEXT,
    rejection_message TEXT,
    booked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (slot_id) REFERENCES appointment_slots(id) ON DELETE CASCADE,
    FOREIGN KEY (student_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE(slot_id, student_user_id)
);

CREATE TABLE IF NOT EXISTS appointment_booking_documents (
    booking_id INTEGER NOT NULL,
    document_type_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (booking_id, document_type_id),
    FOREIGN KEY (booking_id) REFERENCES appointment_bookings(id) ON DELETE CASCADE,
    FOREIGN KEY (document_type_id) REFERENCES document_types(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS appointment_booking_progress_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    progress_note TEXT,
    changed_by_user_id INTEGER,
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES appointment_bookings(id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_user_id INTEGER NOT NULL,
    actor_user_id INTEGER,
    notification_type TEXT NOT NULL,
    reference_code TEXT,
    student_full_name TEXT,
    message TEXT NOT NULL,
    related_booking_id INTEGER,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    read_at TEXT,
    FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (related_booking_id) REFERENCES appointment_bookings(id) ON DELETE SET NULL
);
"""


def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        connection = sqlite3.connect(DATABASE_PATH)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys = ON;')
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    connection = g.pop('db', None)
    if connection is not None:
        connection.close()


def _seed_reference_data(connection: sqlite3.Connection) -> None:
    connection.executemany(
        'INSERT OR IGNORE INTO roles(name) VALUES (?);',
        [('admin',), ('student',)],
    )
    connection.executemany(
        'INSERT OR IGNORE INTO request_statuses(name, display_order) VALUES (?, ?);',
        [
            ('pending', 1),
            ('approved', 2),
            ('processing', 3),
            ('ready_for_release', 4),
            ('released', 5),
            ('rejected', 6),
        ],
    )


def _run_schema_migrations(connection: sqlite3.Connection) -> None:
    # Adds missing columns for older databases before student registration enhancements.
    users_columns = {
        row['name']
        for row in connection.execute('PRAGMA table_info(users);').fetchall()
    }

    if 'student_id' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN student_id TEXT;')
    if 'middle_name' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN middle_name TEXT;')
    if 'suffix' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN suffix TEXT;')
    if 'graduated_program' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN graduated_program TEXT;')
    if 'major' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN major TEXT;')
    if 'year_graduated' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN year_graduated TEXT;')
    if 'address' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN address TEXT;')
    if 'profile_completed' not in users_columns:
        connection.execute('ALTER TABLE users ADD COLUMN profile_completed INTEGER NOT NULL DEFAULT 0;')

    document_type_columns = {
        row['name']
        for row in connection.execute('PRAGMA table_info(document_types);').fetchall()
    }
    if 'category' not in document_type_columns:
        connection.execute("ALTER TABLE document_types ADD COLUMN category TEXT NOT NULL DEFAULT 'Certification';")
    if 'price' not in document_type_columns:
        connection.execute('ALTER TABLE document_types ADD COLUMN price REAL NOT NULL DEFAULT 0;')
    if 'single_request_only' not in document_type_columns:
        connection.execute('ALTER TABLE document_types ADD COLUMN single_request_only INTEGER NOT NULL DEFAULT 0;')
    if 'is_ctc_service' not in document_type_columns:
        connection.execute('ALTER TABLE document_types ADD COLUMN is_ctc_service INTEGER NOT NULL DEFAULT 0;')
    connection.execute(
        """
        UPDATE document_types
        SET category = 'Certification'
        WHERE category IS NULL OR TRIM(category) = '';
        """
    )
    connection.execute(
        """
        UPDATE document_types
        SET category = 'Certification'
        WHERE category NOT IN ('Certification', 'Credentials/record', 'Authentication');
        """
    )
    connection.execute('UPDATE document_types SET single_request_only = 0 WHERE single_request_only IS NULL;')
    connection.execute('UPDATE document_types SET is_ctc_service = 0 WHERE is_ctc_service IS NULL;')
    connection.execute(
        """
        UPDATE document_types
        SET is_ctc_service = 1
        WHERE LOWER(TRIM(name)) IN ('certified true copy', 'ctc');
        """
    )

    # Backward compatibility for older appointment table definitions.
    booking_columns = {
        row['name']
        for row in connection.execute('PRAGMA table_info(appointment_bookings);').fetchall()
    }
    if booking_columns and 'status' not in booking_columns:
        connection.execute("ALTER TABLE appointment_bookings ADD COLUMN status TEXT NOT NULL DEFAULT 'booked';")
    if booking_columns and 'ctc_mode' not in booking_columns:
        connection.execute("ALTER TABLE appointment_bookings ADD COLUMN ctc_mode TEXT NOT NULL DEFAULT 'none';")
    if booking_columns and 'ctc_external_label' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN ctc_external_label TEXT;')
    if booking_columns and 'claim_date' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN claim_date TEXT;')
    if booking_columns and 'claim_requirements' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN claim_requirements TEXT;')
    if booking_columns and 'purpose' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN purpose TEXT;')
    if booking_columns and 'progress_note' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN progress_note TEXT;')
    if booking_columns and 'rejection_message' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN rejection_message TEXT;')
    if booking_columns and 'reference_code' not in booking_columns:
        connection.execute('ALTER TABLE appointment_bookings ADD COLUMN reference_code TEXT;')

    connection.execute(
        """
        UPDATE appointment_bookings
        SET reference_code =
            'DRN-' ||
            COALESCE(strftime('%Y%m%d', booked_at), strftime('%Y%m%d', 'now')) ||
            '-' || printf('%010d', id)
        WHERE reference_code IS NULL OR TRIM(reference_code) = '';
        """
    )
    connection.execute(
        """
        UPDATE appointment_bookings
        SET ctc_mode = 'none'
        WHERE ctc_mode IS NULL OR TRIM(ctc_mode) = '';
        """
    )
    connection.execute(
        """
        UPDATE appointment_bookings
        SET ctc_mode = 'none'
        WHERE ctc_mode NOT IN ('none', 'external', 'apply_selected');
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS appointment_booking_progress_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            progress_note TEXT,
            changed_by_user_id INTEGER,
            changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (booking_id) REFERENCES appointment_bookings(id) ON DELETE CASCADE,
            FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_user_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            notification_type TEXT NOT NULL,
            reference_code TEXT,
            student_full_name TEXT,
            message TEXT NOT NULL,
            related_booking_id INTEGER,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            read_at TEXT,
            FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (related_booking_id) REFERENCES appointment_bookings(id) ON DELETE SET NULL
        );
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    notification_columns = {
        row['name']
        for row in connection.execute('PRAGMA table_info(notifications);').fetchall()
    }
    if notification_columns and 'reference_code' not in notification_columns:
        connection.execute('ALTER TABLE notifications ADD COLUMN reference_code TEXT;')
    if notification_columns and 'student_full_name' not in notification_columns:
        connection.execute('ALTER TABLE notifications ADD COLUMN student_full_name TEXT;')
    if notification_columns and 'related_booking_id' not in notification_columns:
        connection.execute('ALTER TABLE notifications ADD COLUMN related_booking_id INTEGER;')
    if notification_columns and 'is_read' not in notification_columns:
        connection.execute('ALTER TABLE notifications ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0;')
    if notification_columns and 'read_at' not in notification_columns:
        connection.execute('ALTER TABLE notifications ADD COLUMN read_at TEXT;')

    connection.execute(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_student_id_unique ON users(student_id) WHERE student_id IS NOT NULL;'
    )
    connection.execute('CREATE INDEX IF NOT EXISTS idx_appointment_slots_date ON appointment_slots(slot_date);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_appointment_bookings_slot ON appointment_bookings(slot_id);')
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_appointment_bookings_reference_code_unique
        ON appointment_bookings(reference_code)
        WHERE reference_code IS NOT NULL AND reference_code <> '';
        """
    )
    connection.execute('CREATE INDEX IF NOT EXISTS idx_appointment_progress_booking ON appointment_booking_progress_events(booking_id);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_appointment_booking_docs_booking ON appointment_booking_documents(booking_id);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_appointment_booking_docs_doc ON appointment_booking_documents(document_type_id);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_notifications_recipient_created ON notifications(recipient_user_id, created_at DESC);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_notifications_recipient_read_created ON notifications(recipient_user_id, is_read, created_at DESC);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_otps_user_created ON password_reset_otps(user_id, created_at DESC);')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_otps_email_created ON password_reset_otps(email, created_at DESC);')
    connection.execute('UPDATE document_types SET price = 0 WHERE price IS NULL;')
    connection.executemany(
        'INSERT OR IGNORE INTO document_types(category, name, description, price, single_request_only, is_ctc_service) VALUES (?, ?, ?, ?, ?, ?);',
        [
            ('Certification', 'Certificate of General Weighted Average (GWA)', 'Certification for General Weighted Average', 120.0, 0, 0),
            ('Authentication', 'Certificate of Authentication and Verification', 'Document authentication and verification certificate', 150.0, 0, 0),
            ('Certification', 'Certificate of Good Moral Character', 'Good moral character certificate', 100.0, 0, 0),
            ('Certification', 'Track Your Request', 'Track request using your reference number', 0.0, 0, 0),
            ('Certification', 'Certificate of Honor Graduate', 'Honor graduate certificate', 130.0, 0, 0),
            ('Certification', 'Certificate of Units Earned', 'Certification of earned academic units', 120.0, 0, 0),
            ('Certification', 'Certificate of Graduation', 'Graduation certificate', 140.0, 0, 0),
            ('Certification', 'Check the status of your requests using your reference number.', 'Request status checking information', 0.0, 0, 0),
            ('Certification', 'Certificate of Grades', 'Official certificate of grades', 150.0, 0, 0),
            ('Credentials/record', 'Certified True Copy', 'Certified true copy of requested document', 80.0, 0, 1),
            ('Credentials/record', 'Transcript of Records (TOR)', 'Official Transcript of Records', 250.0, 0, 0),
        ],
    )


def init_db() -> None:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON;')
    connection.executescript(SCHEMA_SQL)
    _run_schema_migrations(connection)
    _seed_reference_data(connection)
    connection.commit()
    connection.close()
