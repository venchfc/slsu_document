import calendar
import hashlib
import hmac
import json
from datetime import date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import and_, func, literal, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from models import (
    AppointmentBooking,
    AppointmentBookingDocument,
    AppointmentBookingProgressEvent,
    AppointmentSlot,
    DocumentType,
    DocumentRequest,
    Notification,
    PasswordResetOtp,
    RegistrationOtp,
    Role,
    User,
    UserRole,
    db,
)


REFERENCE_PREFIX = 'DRN'
DOCUMENT_CATEGORIES = {'Certification', 'Credentials/record', 'Authentication'}
CTC_MODES = {'none', 'external', 'apply_selected'}
CLAIM_REQUIREMENT_OPTIONS = [
    {'key': 'documentary_stamp', 'label': 'Documentary Stamp (1 stamp per document)', 'column': 1},
    {'key': 'school_id_valid_id', 'label': 'School ID / Any Valid ID', 'column': 1},
    {'key': 'psa_nso_or_affidavit', 'label': 'Original PSA/NSO, Marriage Certificate Affidavit or', 'column': 1},
    {'key': 'form_137', 'label': 'Form 137', 'column': 1},
    {'key': 'photo_2x2', 'label': '2x2 Picture w/ Nametag (RECENT PHOTO)', 'column': 1},
    {'key': 'transfer_credentials', 'label': 'Transfer Credentials (from previous school of attendance)', 'column': 1},
    {'key': 'police_clearance', 'label': 'Police Clearance', 'column': 2},
    {'key': 'medical_good_moral', 'label': 'Medical/Good Moral Certificate', 'column': 2},
]
PHILIPPINE_TZ = ZoneInfo('Asia/Manila')


def _normalize_document_category(category: str) -> str:
    raw = (category or '').strip()
    if raw in DOCUMENT_CATEGORIES:
        return raw
    return 'Certification'


def _normalize_ctc_mode(ctc_mode: str) -> str:
    raw = (ctc_mode or '').strip().lower()
    if raw in CTC_MODES:
        return raw
    return 'none'


def _verify_scrypt_hash(stored_hash: str, password: str) -> bool:
    # Supports Werkzeug-style hash format: scrypt:n:r:p$salt$hexhash
    try:
        method, salt, expected_hash = stored_hash.split('$', 2)
        _, n, r, p = method.split(':', 3)
        dklen = len(expected_hash) // 2
        if dklen <= 0:
            return False
        derived = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt.encode('utf-8'),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=dklen,
        ).hex()
        return hmac.compare_digest(derived, expected_hash)
    except (ValueError, TypeError):
        return False


def _is_password_match(stored_hash: str, password: str) -> bool:
    try:
        return check_password_hash(stored_hash, password)
    except ValueError:
        if stored_hash.startswith('scrypt:'):
            return _verify_scrypt_hash(stored_hash, password)
        return False


def _dt_to_str(value: Any) -> Any:
    if isinstance(value, datetime):
        local_value = value
        if local_value.tzinfo is None:
            local_value = local_value.replace(tzinfo=ZoneInfo('UTC'))
        return local_value.astimezone(PHILIPPINE_TZ).strftime('%Y-%m-%d %H:%M:%S')
    return value


def _dt_to_long_date(value: Any) -> str:
    if isinstance(value, datetime):
        local_value = value
        if local_value.tzinfo is None:
            local_value = local_value.replace(tzinfo=ZoneInfo('UTC'))
        return local_value.astimezone(PHILIPPINE_TZ).strftime('%B %d, %Y')
    try:
        raw = str(value or '').strip()
        if not raw:
            return ''
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=ZoneInfo('UTC'))
        return parsed.astimezone(PHILIPPINE_TZ).strftime('%B %d, %Y')
    except ValueError:
        return str(value or '').strip()


def _iso_date_or_empty(value: str) -> str:
    raw = str(value or '').strip()
    if not raw:
        return ''
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return ''


def _normalize_claim_requirements(raw_values: list[str]) -> list[str]:
    allowed = {item['key'] for item in CLAIM_REQUIREMENT_OPTIONS}
    selected = []
    seen = set()
    for raw in raw_values:
        key = str(raw or '').strip()
        if key in allowed and key not in seen:
            selected.append(key)
            seen.add(key)
    return selected


def _parse_claim_requirements(raw_value: str) -> list[str]:
    text = str(raw_value or '').strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return _normalize_claim_requirements([str(item) for item in parsed])
    except json.JSONDecodeError:
        pass
    # Backward-compatible fallback for comma-separated values.
    parts = [part.strip() for part in text.split(',') if part.strip()]
    return _normalize_claim_requirements(parts)


def _build_claim_requirement_options(selected_keys: list[str]) -> list[dict[str, Any]]:
    selected_set = set(_normalize_claim_requirements(selected_keys))
    return [
        {
            'key': option['key'],
            'label': option['label'],
            'column': int(option['column']),
            'is_checked': option['key'] in selected_set,
        }
        for option in CLAIM_REQUIREMENT_OPTIONS
    ]


def _build_reference_code(requested_at: datetime | None, booking_id: int) -> str:
    stamp = (requested_at or datetime.utcnow()).strftime('%Y%m%d')
    return f'{REFERENCE_PREFIX}-{stamp}-{booking_id:010d}'


def _build_student_full_name(user: User | None) -> str:
    if not user:
        return ''
    parts = [
        str(user.first_name or '').strip(),
        str(user.middle_name or '').strip(),
        str(user.last_name or '').strip(),
        str(user.suffix or '').strip(),
    ]
    return ' '.join(part for part in parts if part)


def _create_notification(
    recipient_user_id: int,
    notification_type: str,
    message: str,
    reference_code: str | None = None,
    student_full_name: str | None = None,
    related_booking_id: int | None = None,
    actor_user_id: int | None = None,
) -> None:
    trimmed_message = (message or '').strip()
    if not trimmed_message:
        return
    db.session.add(
        Notification(
            recipient_user_id=recipient_user_id,
            actor_user_id=actor_user_id,
            notification_type=(notification_type or 'general').strip() or 'general',
            reference_code=(reference_code or '').strip() or None,
            student_full_name=(student_full_name or '').strip() or None,
            message=trimmed_message,
            related_booking_id=related_booking_id,
            is_read=False,
        )
    )


def get_user_by_email(email: str) -> dict[str, Any] | None:
    user = User.query.filter(func.lower(User.email) == email.lower().strip()).first()
    if not user:
        return None
    return {
        'id': user.id,
        'student_id': user.student_id,
        'email': user.email,
        'password_hash': user.password_hash,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'suffix': user.suffix,
        'graduated_program': user.graduated_program,
        'major': user.major,
        'year_graduated': user.year_graduated,
        'address': user.address,
        'profile_completed': 1 if user.profile_completed else 0,
        'is_active': 1 if user.is_active else 0,
    }


def get_user_by_student_id(student_id: str) -> dict[str, Any] | None:
    user = User.query.filter(User.student_id == student_id.strip()).first()
    if not user:
        return None
    return {
        'id': user.id,
        'student_id': user.student_id,
        'email': user.email,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'suffix': user.suffix,
        'graduated_program': user.graduated_program,
        'major': user.major,
        'year_graduated': user.year_graduated,
        'address': user.address,
        'profile_completed': 1 if user.profile_completed else 0,
        'is_active': 1 if user.is_active else 0,
    }


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    user = User.query.filter(User.id == user_id).first()
    if not user:
        return None
    return {
        'id': user.id,
        'student_id': user.student_id,
        'email': user.email,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'suffix': user.suffix,
        'graduated_program': user.graduated_program,
        'major': user.major,
        'year_graduated': user.year_graduated,
        'address': user.address,
        'profile_completed': 1 if user.profile_completed else 0,
        'is_active': 1 if user.is_active else 0,
        'roles': get_user_roles(user.id),
    }


def get_student_profile(user_id: int) -> dict[str, Any] | None:
    user = User.query.filter(User.id == user_id).first()
    if not user:
        return None
    return {
        'id': user.id,
        'student_id': user.student_id,
        'email': user.email,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'suffix': user.suffix,
        'graduated_program': user.graduated_program,
        'major': user.major,
        'year_graduated': user.year_graduated,
        'address': user.address,
        'profile_completed': 1 if user.profile_completed else 0,
    }


def update_student_profile(
    user_id: int,
    graduated_program: str,
    major: str = '',
    year_graduated: str = '',
    address: str = '',
) -> bool:
    normalized_program = (graduated_program or '').strip()
    normalized_major = (major or '').strip()
    normalized_year = (year_graduated or '').strip()
    normalized_address = (address or '').strip()
    if len(normalized_program) < 3:
        return False
    if len(normalized_year) != 4 or not normalized_year.isdigit():
        return False
    if len(normalized_address) < 8:
        return False

    user = User.query.filter(User.id == user_id).first()
    if not user:
        return False

    user.graduated_program = normalized_program
    user.major = normalized_major or None
    user.year_graduated = normalized_year
    user.address = normalized_address
    user.profile_completed = True
    db.session.commit()
    return True


def get_user_roles(user_id: int) -> list[str]:
    rows = (
        db.session.query(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id)
        .order_by(Role.name)
        .all()
    )
    return [row[0] for row in rows]


def get_user_role_flags_by_email(email: str) -> dict[str, Any] | None:
    normalized_email = (email or '').strip().lower()
    if not normalized_email:
        return None

    user = User.query.filter(func.lower(User.email) == normalized_email).first()
    if not user:
        return None

    roles = set(get_user_roles(int(user.id)))
    return {
        'id': int(user.id),
        'email': user.email,
        'is_active': 1 if user.is_active else 0,
        'is_student': 'student' in roles,
        'is_admin': 'admin' in roles,
    }


def verify_user_password(user_id: int, raw_password: str) -> bool:
    user = User.query.filter(User.id == user_id).first()
    if not user:
        return False
    return _is_password_match(user.password_hash, raw_password or '')


def update_user_password_hash(user_id: int, password_hash: str) -> bool:
    user = User.query.filter(User.id == user_id).first()
    if not user:
        return False
    user.password_hash = (password_hash or '').strip()
    db.session.commit()
    return True


def create_password_reset_otp(
    user_id: int,
    email: str,
    otp_hash: str,
    expiry_minutes: int,
) -> int:
    db.session.query(PasswordResetOtp).filter(
        PasswordResetOtp.user_id == user_id,
        PasswordResetOtp.used_at.is_(None),
    ).update({'used_at': datetime.utcnow()}, synchronize_session=False)

    row = PasswordResetOtp(
        user_id=user_id,
        email=(email or '').strip().lower(),
        otp_hash=otp_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=int(expiry_minutes or 5)),
    )
    db.session.add(row)
    db.session.commit()
    return int(row.id)


def get_password_reset_otp_by_id(reset_otp_id: int) -> dict[str, Any] | None:
    row = PasswordResetOtp.query.filter(PasswordResetOtp.id == reset_otp_id).first()
    if not row:
        return None
    return {
        'id': int(row.id),
        'user_id': int(row.user_id),
        'email': row.email,
        'otp_hash': row.otp_hash,
        'expires_at': row.expires_at.isoformat(timespec='seconds'),
        'attempts': int(row.attempts or 0),
        'used_at': _dt_to_str(row.used_at),
    }


def increment_password_reset_attempt(reset_otp_id: int) -> None:
    row = PasswordResetOtp.query.filter(PasswordResetOtp.id == reset_otp_id).first()
    if not row:
        return
    row.attempts = int(row.attempts or 0) + 1
    db.session.commit()


def mark_password_reset_otp_used(reset_otp_id: int) -> None:
    row = PasswordResetOtp.query.filter(PasswordResetOtp.id == reset_otp_id).first()
    if not row:
        return
    row.used_at = datetime.utcnow()
    db.session.commit()


def authenticate_user(email: str, password: str) -> dict[str, Any] | None:
    user = get_user_by_email(email)
    if not user:
        return None
    if not user['is_active']:
        return None
    if not _is_password_match(user['password_hash'], password):
        return None
    return get_user_by_id(user['id'])


def assign_role(user_id: int, role_name: str) -> None:
    role = Role.query.filter(Role.name == role_name).first()
    if not role:
        raise ValueError(f'Role not found: {role_name}')
    existing = UserRole.query.filter(
        UserRole.user_id == user_id,
        UserRole.role_id == role.id,
    ).first()
    if not existing:
        db.session.add(UserRole(user_id=user_id, role_id=role.id))
        db.session.commit()


def create_student_user(
    student_id: str,
    first_name: str,
    middle_name: str,
    last_name: str,
    suffix: str,
    email: str,
    password_hash: str,
) -> int:
    user = User(
        student_id=student_id.strip(),
        email=email.lower().strip(),
        password_hash=password_hash,
        first_name=first_name.strip(),
        middle_name=middle_name.strip(),
        last_name=last_name.strip(),
        suffix=suffix.strip() or None,
    )
    db.session.add(user)
    db.session.commit()
    return int(user.id)


def create_registration_otp(
    email: str,
    otp_hash: str,
    payload_encrypted: str,
    expiry_minutes: int,
) -> int:
    otp = RegistrationOtp(
        email=email.lower().strip(),
        otp_hash=otp_hash,
        payload_encrypted=payload_encrypted,
        expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes),
    )
    db.session.add(otp)
    db.session.commit()
    return int(otp.id)


def get_registration_otp_by_id(otp_id: int) -> dict[str, Any] | None:
    otp = RegistrationOtp.query.filter(RegistrationOtp.id == otp_id).first()
    if not otp:
        return None
    return {
        'id': otp.id,
        'email': otp.email,
        'otp_hash': otp.otp_hash,
        'payload_encrypted': otp.payload_encrypted,
        'expires_at': otp.expires_at.isoformat(timespec='seconds'),
        'attempts': otp.attempts,
        'used_at': _dt_to_str(otp.used_at),
    }


def increment_registration_attempt(otp_id: int) -> None:
    otp = RegistrationOtp.query.filter(RegistrationOtp.id == otp_id).first()
    if not otp:
        return
    otp.attempts = int(otp.attempts or 0) + 1
    db.session.commit()


def mark_registration_otp_used(otp_id: int) -> None:
    otp = RegistrationOtp.query.filter(RegistrationOtp.id == otp_id).first()
    if not otp:
        return
    otp.used_at = datetime.utcnow()
    db.session.commit()


def get_admin_dashboard_metrics() -> dict[str, Any]:
    total_requests = db.session.query(func.count(AppointmentBooking.id)).scalar() or 0
    approved = (
        db.session.query(func.count(AppointmentBooking.id))
        .filter(
            AppointmentBooking.status.in_(
                [
                    'accepted',
                    'approved',
                    'on_going_validation',
                    'found_in_archive',
                    'in_process',
                    'ready_for_pickup',
                    'claimed',
                    'released',
                ]
            )
        )
        .scalar()
        or 0
    )
    pending = (
        db.session.query(func.count(AppointmentBooking.id))
        .filter(AppointmentBooking.status.in_(['pending', 'booked']))
        .scalar()
        or 0
    )
    rejected = (
        db.session.query(func.count(AppointmentBooking.id))
        .filter(AppointmentBooking.status == 'rejected')
        .scalar()
        or 0
    )

    recent_rows = (
        db.session.query(
            (literal('BK-') + func.cast(AppointmentBooking.id, db.String)).label('request_code'),
            AppointmentBooking.reference_code.label('reference_code'),
            (User.first_name + literal(' ') + User.last_name).label('student_name'),
            func.group_concat(DocumentType.name, ', ').label('document_type'),
            AppointmentBooking.booked_at.label('requested_at'),
            AppointmentBooking.status.label('status'),
        )
        .join(User, User.id == AppointmentBooking.student_user_id)
        .outerjoin(AppointmentBookingDocument, AppointmentBookingDocument.booking_id == AppointmentBooking.id)
        .outerjoin(DocumentType, DocumentType.id == AppointmentBookingDocument.document_type_id)
        .group_by(AppointmentBooking.id, User.first_name, User.last_name, AppointmentBooking.booked_at, AppointmentBooking.status)
        .order_by(AppointmentBooking.booked_at.desc())
        .limit(10)
        .all()
    )

    return {
        'cards': {
            'total': int(total_requests),
            'approved': int(approved),
            'pending': int(pending),
            'rejected': int(rejected),
        },
        'recent_requests': [
            {
                'request_code': row.request_code,
                'reference_code': row.reference_code,
                'student_name': row.student_name,
                'document_type': row.document_type,
                'requested_at': _dt_to_str(row.requested_at),
                'status': row.status,
            }
            for row in recent_rows
        ],
    }


def get_document_types() -> list[dict[str, Any]]:
    return get_document_types_for_admin()


def get_document_types_for_admin() -> list[dict[str, Any]]:
    rows = DocumentType.query.order_by(DocumentType.name.asc()).all()
    return [
        {
            'id': row.id,
            'category': _normalize_document_category(getattr(row, 'category', 'Certification')),
            'name': row.name,
            'description': row.description,
            'price': float(row.price or 0),
            'is_active': 1 if row.is_active else 0,
            'single_request_only': 1 if bool(getattr(row, 'single_request_only', False)) else 0,
            'is_ctc_service': 1 if bool(getattr(row, 'is_ctc_service', False)) else 0,
        }
        for row in rows
    ]


def get_document_types_for_student() -> list[dict[str, Any]]:
    rows = DocumentType.query.filter(DocumentType.is_active.is_(True)).order_by(DocumentType.name.asc()).all()
    return [
        {
            'id': row.id,
            'category': _normalize_document_category(getattr(row, 'category', 'Certification')),
            'name': row.name,
            'description': row.description,
            'price': float(row.price or 0),
            'single_request_only': 1 if bool(getattr(row, 'single_request_only', False)) else 0,
            'is_ctc_service': 1 if bool(getattr(row, 'is_ctc_service', False)) else 0,
        }
        for row in rows
    ]


def get_document_type_by_id(document_type_id: int) -> dict[str, Any] | None:
    row = DocumentType.query.filter(DocumentType.id == document_type_id).first()
    if not row:
        return None
    return {
        'id': row.id,
        'category': _normalize_document_category(getattr(row, 'category', 'Certification')),
        'name': row.name,
        'description': row.description,
        'price': float(row.price or 0),
        'is_active': 1 if row.is_active else 0,
        'single_request_only': 1 if bool(getattr(row, 'single_request_only', False)) else 0,
        'is_ctc_service': 1 if bool(getattr(row, 'is_ctc_service', False)) else 0,
    }


def get_document_type_by_name(name: str) -> dict[str, Any] | None:
    row = DocumentType.query.filter(func.lower(DocumentType.name) == name.strip().lower()).first()
    if not row:
        return None
    return {
        'id': row.id,
        'category': _normalize_document_category(getattr(row, 'category', 'Certification')),
        'name': row.name,
        'description': row.description,
        'price': float(row.price or 0),
        'is_active': 1 if row.is_active else 0,
        'single_request_only': 1 if bool(getattr(row, 'single_request_only', False)) else 0,
        'is_ctc_service': 1 if bool(getattr(row, 'is_ctc_service', False)) else 0,
    }


def create_document_type(
    category: str,
    name: str,
    description: str,
    price: float,
    is_active: bool,
    single_request_only: bool,
    is_ctc_service: bool,
) -> int:
    row = DocumentType(
        category=_normalize_document_category(category),
        name=name.strip(),
        description=description.strip() or None,
        price=float(price),
        is_active=bool(is_active),
        single_request_only=bool(single_request_only),
        is_ctc_service=bool(is_ctc_service),
    )
    db.session.add(row)
    db.session.commit()
    return int(row.id)


def update_document_type(
    document_type_id: int,
    category: str,
    name: str,
    description: str,
    price: float,
    is_active: bool,
    single_request_only: bool,
    is_ctc_service: bool,
) -> None:
    row = DocumentType.query.filter(DocumentType.id == document_type_id).first()
    if not row:
        return
    row.category = _normalize_document_category(category)
    row.name = name.strip()
    row.description = description.strip() or None
    row.price = float(price)
    row.is_active = bool(is_active)
    row.single_request_only = bool(single_request_only)
    row.is_ctc_service = bool(is_ctc_service)
    db.session.commit()


def delete_document_type(document_type_id: int) -> tuple[bool, str]:
    row = DocumentType.query.filter(DocumentType.id == document_type_id).first()
    if not row:
        return False, 'Document type not found.'

    booking_usage_count = (
        AppointmentBookingDocument.query.filter(
            AppointmentBookingDocument.document_type_id == document_type_id
        ).count()
    )
    legacy_usage_count = (
        DocumentRequest.query.filter(
            DocumentRequest.document_type_id == document_type_id
        ).count()
    )
    if int(booking_usage_count or 0) > 0 or int(legacy_usage_count or 0) > 0:
        return False, 'This document type is already used in requests and cannot be deleted. Set it to inactive instead.'

    db.session.delete(row)
    db.session.commit()
    return True, 'Document type deleted successfully.'


def set_appointment_slot(slot_date: str, total_slots: int, admin_user_id: int | None) -> None:
    try:
        selected_date = date.fromisoformat(slot_date)
    except ValueError as exc:
        raise ValueError('Invalid slot date format.') from exc

    if selected_date < date.today():
        raise ValueError('Past dates cannot be configured for slots.')

    row = AppointmentSlot.query.filter(AppointmentSlot.slot_date == slot_date).first()
    if row:
        row.total_slots = int(total_slots)
        row.updated_at = datetime.utcnow()
    else:
        row = AppointmentSlot(
            slot_date=slot_date,
            total_slots=int(total_slots),
            created_by_user_id=admin_user_id,
            updated_at=datetime.utcnow(),
        )
        db.session.add(row)
    db.session.commit()


def get_appointment_slots_by_month(year: int, month: int) -> dict[str, dict[str, int]]:
    start_date = date(year, month, 1)
    _, last_day = calendar.monthrange(year, month)
    end_date = date(year, month, last_day)

    rows = (
        db.session.query(
            AppointmentSlot.slot_date,
            AppointmentSlot.total_slots,
            func.count(AppointmentBooking.id).label('used_slots'),
        )
        .outerjoin(
            AppointmentBooking,
            and_(
                AppointmentBooking.slot_id == AppointmentSlot.id,
                AppointmentBooking.status != 'rejected',
            ),
        )
        .filter(AppointmentSlot.slot_date >= start_date.isoformat(), AppointmentSlot.slot_date <= end_date.isoformat())
        .group_by(AppointmentSlot.id, AppointmentSlot.slot_date, AppointmentSlot.total_slots)
        .order_by(AppointmentSlot.slot_date.asc())
        .all()
    )

    result: dict[str, dict[str, int]] = {}
    for row in rows:
        used = int(row.used_slots or 0)
        total = int(row.total_slots or 0)
        result[row.slot_date] = {
            'total_slots': total,
            'used_slots': used,
            'available_slots': max(total - used, 0),
        }
    return result


def get_upcoming_appointment_slots(limit: int = 30) -> list[dict[str, Any]]:
    rows = (
        db.session.query(
            AppointmentSlot.id,
            AppointmentSlot.slot_date,
            AppointmentSlot.total_slots,
            func.count(AppointmentBooking.id).label('used_slots'),
        )
        .outerjoin(
            AppointmentBooking,
            and_(
                AppointmentBooking.slot_id == AppointmentSlot.id,
                AppointmentBooking.status != 'rejected',
            ),
        )
        .filter(AppointmentSlot.slot_date >= date.today().isoformat())
        .group_by(AppointmentSlot.id, AppointmentSlot.slot_date, AppointmentSlot.total_slots)
        .order_by(AppointmentSlot.slot_date.asc())
        .limit(limit)
        .all()
    )

    slots: list[dict[str, Any]] = []
    for row in rows:
        used = int(row.used_slots or 0)
        total = int(row.total_slots or 0)
        slots.append(
            {
                'id': row.id,
                'slot_date': row.slot_date,
                'total_slots': total,
                'used_slots': used,
                'available_slots': max(total - used, 0),
            }
        )
    return slots


def get_student_appointment_bookings(student_user_id: int) -> list[dict[str, Any]]:
    rows = (
        db.session.query(
            AppointmentBooking.id,
            AppointmentBooking.reference_code,
            AppointmentSlot.slot_date,
            AppointmentBooking.purpose,
            AppointmentBooking.status,
            AppointmentBooking.progress_note,
            AppointmentBooking.rejection_message,
            AppointmentBooking.booked_at,
            func.group_concat(DocumentType.name, ', ').label('document_names'),
        )
        .join(AppointmentSlot, AppointmentSlot.id == AppointmentBooking.slot_id)
        .outerjoin(AppointmentBookingDocument, AppointmentBookingDocument.booking_id == AppointmentBooking.id)
        .outerjoin(DocumentType, DocumentType.id == AppointmentBookingDocument.document_type_id)
        .filter(AppointmentBooking.student_user_id == student_user_id)
        .group_by(
            AppointmentBooking.id,
            AppointmentBooking.reference_code,
            AppointmentSlot.slot_date,
            AppointmentBooking.purpose,
            AppointmentBooking.status,
            AppointmentBooking.progress_note,
            AppointmentBooking.rejection_message,
            AppointmentBooking.booked_at,
        )
        .order_by(AppointmentSlot.slot_date.desc())
        .all()
    )

    return [
        {
            'id': row.id,
            'reference_code': row.reference_code,
            'slot_date': row.slot_date,
            'purpose': row.purpose,
            'status': row.status,
            'progress_note': row.progress_note,
            'rejection_message': row.rejection_message,
            'booked_at': _dt_to_str(row.booked_at),
            'document_names': row.document_names,
        }
        for row in rows
    ]


def create_appointment_booking_atomic(
    slot_date: str,
    student_user_id: int,
    document_type_ids: list[int],
    purpose: str,
    ctc_mode: str = 'none',
    ctc_external_label: str = '',
) -> tuple[bool, str]:
    try:
        selected_date = date.fromisoformat(slot_date)
    except ValueError:
        return False, 'Invalid request date format.'

    if selected_date < date.today():
        return False, 'Past dates cannot be requested. Please choose today or a future date.'

    cleaned_purpose = (purpose or '').strip()
    if len(cleaned_purpose) < 3:
        return False, 'Purpose is required.'

    normalized_ctc_mode = _normalize_ctc_mode(ctc_mode)
    normalized_ctc_external_label = (ctc_external_label or '').strip()
    if normalized_ctc_mode == 'external' and len(normalized_ctc_external_label) < 3:
        return False, 'Please provide the original document name for CTC.'

    doc_ids = sorted({int(doc_id) for doc_id in document_type_ids if doc_id})
    if not doc_ids and normalized_ctc_mode != 'external':
        return False, 'Please select at least one document type.'

    slot = AppointmentSlot.query.filter(AppointmentSlot.slot_date == slot_date).first()
    if not slot:
        return False, 'No slot configured for the selected date.'

    total_slots = int(slot.total_slots or 0)
    if total_slots <= 0:
        return False, 'This date has no available request slots.'

    existing_booking = AppointmentBooking.query.filter(
        AppointmentBooking.slot_id == slot.id,
        AppointmentBooking.student_user_id == student_user_id,
    ).first()
    if existing_booking:
        return False, 'You already submitted a request for this date.'

    used_count = (
        AppointmentBooking.query.filter(
            AppointmentBooking.slot_id == slot.id,
            AppointmentBooking.status != 'rejected',
        ).count()
    )
    if int(used_count) >= total_slots:
        return False, 'Slot is already full.'

    valid_docs = (
        DocumentType.query.filter(
            DocumentType.is_active.is_(True),
            DocumentType.id.in_(doc_ids),
        ).all()
    )
    valid_doc_ids = {int(row.id) for row in valid_docs}
    if len(valid_doc_ids) != len(doc_ids):
        return False, 'One or more selected document types are invalid.'

    if any(bool(getattr(row, 'is_ctc_service', False)) for row in valid_docs):
        return False, 'CTC service must be configured through the CTC options only.'

    if normalized_ctc_mode == 'apply_selected' and not valid_docs:
        return False, 'Select at least one requested document to apply CTC.'

    single_only_docs = [row for row in valid_docs if bool(getattr(row, 'single_request_only', False))]
    if single_only_docs and len(valid_docs) > 1:
        return False, 'One selected document is marked as single request only and cannot be combined with other documents.'

    selected_names = {str(row.name).strip().lower() for row in valid_docs}
    if (
        'transcript of records (tor)' in selected_names
        and 'certificate of authentication and verification' in selected_names
    ):
        return False, 'TOR cannot be requested together with Certificate of Authentication and Verification.'

    try:
        student = User.query.filter(User.id == student_user_id).first()
        booking = AppointmentBooking(
            slot_id=slot.id,
            student_user_id=student_user_id,
            purpose=cleaned_purpose,
            status='pending',
            ctc_mode=normalized_ctc_mode,
            ctc_external_label=normalized_ctc_external_label or None,
        )
        db.session.add(booking)
        db.session.flush()
        booking.reference_code = _build_reference_code(booking.booked_at, int(booking.id))

        for doc_id in doc_ids:
            db.session.add(
                AppointmentBookingDocument(
                    booking_id=int(booking.id),
                    document_type_id=doc_id,
                )
            )

        db.session.add(
            AppointmentBookingProgressEvent(
                booking_id=int(booking.id),
                status='pending',
                progress_note='Request submitted by student.',
                changed_by_user_id=student_user_id,
            )
        )

        admin_user_rows = (
            db.session.query(User.id)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .filter(Role.name == 'admin', User.is_active.is_(True))
            .all()
        )
        student_full_name = _build_student_full_name(student)
        _create_notification(
            recipient_user_id=student_user_id,
            actor_user_id=student_user_id,
            notification_type='request_submitted',
            reference_code=booking.reference_code,
            student_full_name=student_full_name,
            message='Your request has been submitted! You can see it anytime in your Student Dashboard (PORTAL). To follow its progress, just open the Request Progress Tracker and check for updates until your document is ready.',
            related_booking_id=int(booking.id),
        )
        for admin_row in admin_user_rows:
            _create_notification(
                recipient_user_id=int(admin_row.id),
                actor_user_id=student_user_id,
                notification_type='request_created',
                reference_code=booking.reference_code,
                student_full_name=student_full_name,
                message='New document request received. Please review the request.',
                related_booking_id=int(booking.id),
            )

        db.session.commit()
        return True, 'Document request submitted successfully.'
    except IntegrityError:
        db.session.rollback()
        return False, 'Unable to submit this request for the selected date. Please try again.'


def get_admin_requests(status_filter: str = 'all', search: str = '') -> list[dict[str, Any]]:
    query = (
        db.session.query(
            AppointmentBooking.id.label('booking_id'),
            AppointmentBooking.reference_code.label('reference_code'),
            User.student_id.label('student_id'),
            (User.first_name + literal(' ') + User.last_name).label('student_name'),
            func.group_concat(DocumentType.name, ', ').label('document_type'),
            AppointmentBooking.booked_at.label('date_requested'),
            AppointmentBooking.status.label('status'),
            AppointmentBooking.purpose.label('purpose'),
            AppointmentBooking.progress_note.label('progress_note'),
            AppointmentBooking.rejection_message.label('rejection_message'),
        )
        .join(User, User.id == AppointmentBooking.student_user_id)
        .outerjoin(AppointmentBookingDocument, AppointmentBookingDocument.booking_id == AppointmentBooking.id)
        .outerjoin(DocumentType, DocumentType.id == AppointmentBookingDocument.document_type_id)
    )

    normalized_status = (status_filter or 'all').strip().lower()
    if normalized_status == 'archive':
        query = query.filter(AppointmentBooking.status.in_(['claimed', 'rejected']))
    elif normalized_status and normalized_status != 'all':
        query = query.filter(AppointmentBooking.status == normalized_status)
    else:
        query = query.filter(~AppointmentBooking.status.in_(['claimed', 'rejected']))

    normalized_search = (search or '').strip().lower()
    if normalized_search:
        like_value = f'%{normalized_search}%'
        query = query.filter(
            or_(
                func.lower(func.coalesce(User.student_id, '')).like(like_value),
                func.lower(func.coalesce(AppointmentBooking.reference_code, '')).like(like_value),
                func.lower(User.first_name + literal(' ') + User.last_name).like(like_value),
                func.lower(func.coalesce(DocumentType.name, '')).like(like_value),
                func.lower(func.coalesce(AppointmentBooking.purpose, '')).like(like_value),
            )
        )

    rows = (
        query.group_by(
            AppointmentBooking.id,
            AppointmentBooking.reference_code,
            User.student_id,
            User.first_name,
            User.last_name,
            AppointmentBooking.booked_at,
            AppointmentBooking.status,
            AppointmentBooking.purpose,
            AppointmentBooking.progress_note,
            AppointmentBooking.rejection_message,
        )
        .order_by(AppointmentBooking.booked_at.desc(), AppointmentBooking.id.desc())
        .all()
    )

    return [
        {
            'booking_id': row.booking_id,
            'reference_code': row.reference_code,
            'student_id': row.student_id,
            'student_name': row.student_name,
            'document_type': row.document_type,
            'date_requested': _dt_to_str(row.date_requested),
            'status': row.status,
            'purpose': row.purpose,
            'progress_note': row.progress_note,
            'rejection_message': row.rejection_message,
        }
        for row in rows
    ]


def _derive_request_type_flags(document_names: list[str]) -> dict[str, bool]:
    flags = {
        'certification': False,
        'credentials_records': False,
        'authentication': False,
    }
    for name in document_names:
        normalized = str(name or '').strip().lower()
        if not normalized:
            continue
        if any(keyword in normalized for keyword in ['authentication', 'cav']):
            flags['authentication'] = True
            continue
        if any(
            keyword in normalized
            for keyword in ['tor', 'transcript', 'diploma', 'copy of grades', 'form 137', 'transfer credentials', 'credentials']
        ):
            flags['credentials_records'] = True
            continue
        flags['certification'] = True
    if not any(flags.values()):
        flags['certification'] = True
    return flags


def _build_request_form_category_items(requested_docs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        'Certification': [],
        'Credentials/record': [],
        'Authentication': [],
    }
    seen_names: dict[str, set[str]] = {
        'Certification': set(),
        'Credentials/record': set(),
        'Authentication': set(),
    }

    requested_name_set = {
        str(item.get('name') or '').strip().lower()
        for item in requested_docs
        if str(item.get('name') or '').strip()
    }
    active_rows = (
        DocumentType.query.filter(DocumentType.is_active.is_(True))
        .order_by(DocumentType.name.asc())
        .all()
    )
    for row in active_rows:
        name = str(row.name or '').strip()
        if not name:
            continue
        category = _normalize_document_category(getattr(row, 'category', 'Certification'))
        normalized_name = name.lower()
        if normalized_name in seen_names[category]:
            continue
        grouped[category].append(
            {
                'name': name,
                'is_requested': normalized_name in requested_name_set,
                'price': float(getattr(row, 'price', 0) or 0),
            }
        )
        seen_names[category].add(normalized_name)

    # Keep historical accuracy: requested docs remain visible even if later set inactive.
    for item in requested_docs:
        name = str(item.get('name') or '').strip()
        if not name:
            continue
        category = _normalize_document_category(str(item.get('category') or 'Certification'))
        normalized_name = name.lower()

        if normalized_name in seen_names[category]:
            for existing in grouped[category]:
                if str(existing.get('name') or '').strip().lower() == normalized_name:
                    existing['is_requested'] = True
                    requested_price = float(item.get('price') or 0)
                    if requested_price > 0:
                        existing['price'] = requested_price
                    break
            continue

        grouped[category].append(
            {
                'name': name,
                'is_requested': True,
                'price': float(item.get('price') or 0),
            }
        )
        seen_names[category].add(normalized_name)

    return {
        'certification_items': grouped['Certification'],
        'credentials_records_items': grouped['Credentials/record'],
        'authentication_items': grouped['Authentication'],
    }


def get_admin_request_form_data(booking_id: int) -> dict[str, Any] | None:
    row = (
        db.session.query(
            AppointmentBooking.id.label('booking_id'),
            AppointmentBooking.reference_code.label('reference_code'),
            AppointmentBooking.booked_at.label('requested_at'),
            AppointmentBooking.claim_date.label('claim_date'),
            AppointmentBooking.claim_requirements.label('claim_requirements'),
            AppointmentBooking.purpose.label('purpose'),
            AppointmentBooking.ctc_mode.label('ctc_mode'),
            AppointmentBooking.ctc_external_label.label('ctc_external_label'),
            AppointmentBooking.status.label('status'),
            User.student_id.label('student_id'),
            User.email.label('student_email'),
            User.last_name.label('last_name'),
            User.first_name.label('first_name'),
            User.middle_name.label('middle_name'),
            User.graduated_program.label('program_course'),
            User.major.label('major'),
            User.year_graduated.label('year_graduated'),
            User.address.label('home_address'),
            func.group_concat(DocumentType.name, ', ').label('document_names'),
        )
        .join(User, User.id == AppointmentBooking.student_user_id)
        .outerjoin(AppointmentBookingDocument, AppointmentBookingDocument.booking_id == AppointmentBooking.id)
        .outerjoin(DocumentType, DocumentType.id == AppointmentBookingDocument.document_type_id)
        .filter(AppointmentBooking.id == booking_id)
        .group_by(
            AppointmentBooking.id,
            AppointmentBooking.reference_code,
            AppointmentBooking.booked_at,
            AppointmentBooking.claim_date,
            AppointmentBooking.claim_requirements,
            AppointmentBooking.purpose,
            AppointmentBooking.ctc_mode,
            AppointmentBooking.ctc_external_label,
            AppointmentBooking.status,
            User.student_id,
            User.email,
            User.last_name,
            User.first_name,
            User.middle_name,
            User.graduated_program,
            User.major,
            User.year_graduated,
            User.address,
        )
        .first()
    )
    if not row:
        return None

    requested_rows = (
        db.session.query(
            DocumentType.name.label('name'),
            DocumentType.category.label('category'),
            DocumentType.price.label('price'),
        )
        .join(AppointmentBookingDocument, AppointmentBookingDocument.document_type_id == DocumentType.id)
        .filter(AppointmentBookingDocument.booking_id == booking_id)
        .order_by(DocumentType.name.asc())
        .all()
    )
    requested_docs = [
        {
            'name': str(doc_row.name or '').strip(),
            'category': _normalize_document_category(str(getattr(doc_row, 'category', 'Certification') or 'Certification')),
            'price': float(getattr(doc_row, 'price', 0) or 0),
        }
        for doc_row in requested_rows
        if str(doc_row.name or '').strip()
    ]

    doc_names = [doc['name'] for doc in requested_docs]
    if not doc_names:
        doc_names = [part.strip() for part in str(row.document_names or '').split(',') if part.strip()]

    flags = {
        'certification': any(doc['category'] == 'Certification' for doc in requested_docs),
        'credentials_records': any(doc['category'] == 'Credentials/record' for doc in requested_docs),
        'authentication': any(doc['category'] == 'Authentication' for doc in requested_docs),
    }
    if not any(flags.values()):
        flags = _derive_request_type_flags(doc_names)

    dynamic_items = _build_request_form_category_items(requested_docs)
    return {
        'booking_id': row.booking_id,
        'reference_code': row.reference_code,
        'requested_at': _dt_to_str(row.requested_at),
        'requested_date_display': _dt_to_long_date(row.requested_at),
        'claim_date': _iso_date_or_empty(str(row.claim_date or '')),
        'claim_date_display': _dt_to_long_date(str(row.claim_date or '')),
        'claim_requirements': _parse_claim_requirements(str(row.claim_requirements or '')),
        'purpose': row.purpose,
        'ctc_mode': _normalize_ctc_mode(str(row.ctc_mode or 'none')),
        'ctc_external_label': (row.ctc_external_label or '').strip(),
        'student_id': row.student_id,
        'student_email': row.student_email,
        'last_name': row.last_name,
        'first_name': row.first_name,
        'middle_name': row.middle_name,
        'program_course': row.program_course,
        'major': row.major,
        'year_graduated': row.year_graduated,
        'home_address': row.home_address,
        'status': row.status,
        'document_names': doc_names,
        'check_certification': 1 if flags['certification'] else 0,
        'check_credentials_records': 1 if flags['credentials_records'] else 0,
        'check_authentication': 1 if flags['authentication'] else 0,
        'certification_items': dynamic_items['certification_items'],
        'credentials_records_items': dynamic_items['credentials_records_items'],
        'authentication_items': dynamic_items['authentication_items'],
    }


def get_admin_claim_slip_data(booking_id: int) -> dict[str, Any] | None:
    form_data = get_admin_request_form_data(booking_id)
    if not form_data:
        return None

    first_name = str(form_data.get('first_name') or '').strip()
    middle_name = str(form_data.get('middle_name') or '').strip()
    last_name = str(form_data.get('last_name') or '').strip()
    full_name = ' '.join(part for part in [first_name, middle_name, last_name] if part)

    return {
        'booking_id': form_data.get('booking_id'),
        'reference_code': form_data.get('reference_code') or '',
        'student_email': form_data.get('student_email') or '',
        'student_full_name': full_name,
        'program_course': form_data.get('program_course') or '',
        'date_of_request': form_data.get('requested_date_display') or '',
        'status': form_data.get('status') or '',
        'claim_date_iso': form_data.get('claim_date') or '',
        'claim_date': form_data.get('claim_date_display') or '',
        'claim_requirement_options': _build_claim_requirement_options(form_data.get('claim_requirements') or []),
        'check_certification': int(form_data.get('check_certification') or 0),
        'check_credentials_records': int(form_data.get('check_credentials_records') or 0),
        'check_authentication': int(form_data.get('check_authentication') or 0),
        'certification_items': form_data.get('certification_items') or [],
        'credentials_records_items': form_data.get('credentials_records_items') or [],
        'authentication_items': form_data.get('authentication_items') or [],
    }


def update_booking_claim_details(booking_id: int, claim_date: str, claim_requirements: list[str]) -> bool:
    booking = AppointmentBooking.query.filter(AppointmentBooking.id == booking_id).first()
    if not booking:
        return False

    normalized_claim_date = _iso_date_or_empty(claim_date)
    if not normalized_claim_date:
        return False

    normalized_requirements = _normalize_claim_requirements(claim_requirements)

    booking.claim_date = normalized_claim_date
    booking.claim_requirements = json.dumps(normalized_requirements)
    db.session.commit()
    return True


def update_booking_claim_date(booking_id: int, claim_date: str) -> bool:
    # Backward-compatible wrapper.
    return update_booking_claim_details(booking_id, claim_date, [])


def update_booking_status(
    booking_id: int,
    new_status: str,
    rejection_message: str = '',
    progress_note: str = '',
    changed_by_user_id: int | None = None,
) -> bool:
    allowed = {
        'pending',
        'accepted',
        'in_process',
        'ready_for_pickup',
        'claimed',
        'rejected',
    }
    normalized = (new_status or '').strip().lower()
    if normalized not in allowed:
        return False

    booking = AppointmentBooking.query.filter(AppointmentBooking.id == booking_id).first()
    if not booking:
        return False

    current_status = str(booking.status or '').strip().lower()
    sequential_next = {
        'pending': {'pending', 'accepted', 'rejected'},
        'accepted': {'accepted', 'in_process', 'rejected'},
        'on_going_validation': {'on_going_validation', 'in_process', 'rejected'},
        'found_in_archive': {'found_in_archive', 'in_process', 'rejected'},
        'in_process': {'in_process', 'ready_for_pickup', 'rejected'},
        'ready_for_pickup': {'ready_for_pickup', 'claimed', 'rejected'},
        'claimed': {'claimed'},
        'rejected': {'rejected'},
    }
    if normalized not in sequential_next.get(current_status, {current_status, 'rejected'}):
        return False

    normalized_message = (rejection_message or '').strip()
    if normalized == 'rejected' and not normalized_message:
        return False

    progress_note = (progress_note or '').strip()

    booking.status = normalized
    booking.rejection_message = normalized_message if normalized == 'rejected' else None
    booking.progress_note = progress_note or None

    event_note = progress_note or normalized_message or None
    db.session.add(
        AppointmentBookingProgressEvent(
            booking_id=booking_id,
            status=normalized,
            progress_note=event_note,
            changed_by_user_id=changed_by_user_id,
        )
    )

    status_label = normalized.replace('_', ' ').title()
    student_notification_message = event_note or f"Your document request is {status_label}."
    _create_notification(
        recipient_user_id=int(booking.student_user_id),
        actor_user_id=changed_by_user_id,
        notification_type='status_updated',
        reference_code=booking.reference_code,
        message=student_notification_message,
        related_booking_id=booking_id,
    )

    db.session.commit()
    return True


def get_booking_progress_events(booking_id: int) -> list[dict[str, Any]]:
    rows = (
        db.session.query(
            AppointmentBookingProgressEvent.id,
            AppointmentBookingProgressEvent.booking_id,
            AppointmentBookingProgressEvent.status,
            AppointmentBookingProgressEvent.progress_note,
            AppointmentBookingProgressEvent.changed_at,
        )
        .filter(AppointmentBookingProgressEvent.booking_id == booking_id)
        .order_by(AppointmentBookingProgressEvent.changed_at.asc(), AppointmentBookingProgressEvent.id.asc())
        .all()
    )

    events = [
        {
            'id': row.id,
            'booking_id': row.booking_id,
            'status': row.status,
            'progress_note': row.progress_note,
            'changed_at': _dt_to_str(row.changed_at),
        }
        for row in rows
    ]
    if events:
        return events

    fallback = AppointmentBooking.query.filter(AppointmentBooking.id == booking_id).first()
    if not fallback:
        return []

    note = (fallback.progress_note or '').strip() or (fallback.rejection_message or '').strip()
    if not note:
        note = f"Current status: {str(fallback.status or 'pending').replace('_', ' ').title()}"

    return [
        {
            'id': 0,
            'booking_id': booking_id,
            'status': fallback.status or 'pending',
            'progress_note': note,
            'changed_at': _dt_to_str(fallback.booked_at),
        }
    ]


def get_notification_unread_count(recipient_user_id: int) -> int:
    count = (
        Notification.query.filter(
            Notification.recipient_user_id == recipient_user_id,
            Notification.is_read.is_(False),
        )
        .count()
    )
    return int(count or 0)


def get_notifications_for_user(recipient_user_id: int, is_read: bool, limit: int = 20) -> list[dict[str, Any]]:
    normalized_limit = max(1, min(int(limit or 20), 50))
    rows = (
        Notification.query.filter(
            Notification.recipient_user_id == recipient_user_id,
            Notification.is_read.is_(bool(is_read)),
        )
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .limit(normalized_limit)
        .all()
    )
    return [
        {
            'id': row.id,
            'notification_type': row.notification_type,
            'reference_code': row.reference_code,
            'student_full_name': row.student_full_name,
            'message': row.message,
            'related_booking_id': row.related_booking_id,
            'is_read': 1 if row.is_read else 0,
            'created_at': _dt_to_str(row.created_at),
            'read_at': _dt_to_str(row.read_at),
        }
        for row in rows
    ]


def mark_notification_as_read(recipient_user_id: int, notification_id: int) -> bool:
    row = Notification.query.filter(
        Notification.id == notification_id,
        Notification.recipient_user_id == recipient_user_id,
    ).first()
    if not row:
        return False
    if not row.is_read:
        row.is_read = True
        row.read_at = datetime.utcnow()
        db.session.commit()
    return True


def mark_all_notifications_as_read(recipient_user_id: int) -> int:
    rows = Notification.query.filter(
        Notification.recipient_user_id == recipient_user_id,
        Notification.is_read.is_(False),
    ).all()
    if not rows:
        return 0
    now = datetime.utcnow()
    for row in rows:
        row.is_read = True
        row.read_at = now
    db.session.commit()
    return len(rows)
