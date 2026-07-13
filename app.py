import os
import calendar
from datetime import date, datetime, timedelta
import sqlite3
from pathlib import Path
import base64

from flask import Flask, g, flash, jsonify, redirect, render_template, request, session, url_for
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

from auth_utils import load_current_user, login_required, login_user, logout_user, role_required
from db import DATABASE_PATH, close_db, init_db
from email_service import send_claim_slip_email, send_password_reset_otp_email, send_registration_otp_email
from forms import (
    AppointmentBookingForm,
    AppointmentSlotForm,
    ForgotPasswordRequestForm,
    LoginForm,
    ResetPasswordForm,
    StudentChangePasswordForm,
    StudentProfileForm,
    StudentRegistrationForm,
    VerifyOtpForm,
)
from models import db
from repositories import (
    assign_role,
    authenticate_user,
    create_password_reset_otp,
    create_document_type,
    create_registration_otp,
    create_student_user,
    delete_document_type,
    get_admin_dashboard_metrics,
    get_document_type_by_id,
    get_document_type_by_name,
    get_document_types,
    get_document_types_for_student,
    get_registration_otp_by_id,
    get_student_profile,
    get_student_appointment_bookings,
    get_upcoming_appointment_slots,
    get_user_by_email,
    get_user_by_id,
    get_user_by_student_id,
    increment_registration_attempt,
    mark_registration_otp_used,
    create_appointment_booking_atomic,
    get_appointment_slots_by_month,
    get_admin_requests,
    get_admin_request_form_data,
    get_admin_claim_slip_data,
    get_booking_progress_events,
    get_notifications_for_user,
    get_notification_unread_count,
    get_password_reset_otp_by_id,
    mark_all_notifications_as_read,
    mark_password_reset_otp_used,
    mark_notification_as_read,
    increment_password_reset_attempt,
    set_appointment_slot,
    update_booking_claim_details,
    update_booking_status,
    get_user_role_flags_by_email,
    update_student_profile,
    update_user_password_hash,
    update_document_type,
    verify_user_password,
)
from forms import DocumentTypeForm
from security_utils import decrypt_json, encrypt_json, generate_otp_code

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)
app.config['OTP_EXPIRY_MINUTES'] = int(os.environ.get('OTP_EXPIRY_MINUTES', '5'))
app.config['OTP_MAX_ATTEMPTS'] = int(os.environ.get('OTP_MAX_ATTEMPTS', '5'))
app.config['PASSWORD_RESET_OTP_EXPIRY_MINUTES'] = int(os.environ.get('PASSWORD_RESET_OTP_EXPIRY_MINUTES', '5'))
app.config['PASSWORD_RESET_MAX_ATTEMPTS'] = int(os.environ.get('PASSWORD_RESET_MAX_ATTEMPTS', '5'))
app.config['PASSWORD_RESET_AUTH_MINUTES'] = int(os.environ.get('PASSWORD_RESET_AUTH_MINUTES', '10'))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DATABASE_PATH.as_posix()}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
init_db()
app.teardown_appcontext(close_db)


REQUEST_PROGRESS_STEPS = [
    'pending',
    'accepted',
    'on_going_validation',
    'found_in_archive',
    'in_process',
    'ready_for_pickup',
    'claimed',
]

REQUEST_PROGRESS_META = [
    {'key': 'pending', 'label': 'Pending', 'short': 'Pending'},
    {'key': 'accepted', 'label': 'Accepted', 'short': 'Accepted'},
    {'key': 'on_going_validation', 'label': 'On Going Validation', 'short': 'Validation'},
    {'key': 'found_in_archive', 'label': 'Found In Archive', 'short': 'Archive'},
    {'key': 'in_process', 'label': 'In Process', 'short': 'Process'},
    {'key': 'ready_for_pickup', 'label': 'Ready For Pickup', 'short': 'Ready'},
    {'key': 'claimed', 'label': 'Claimed', 'short': 'Claimed'},
]

TRACKER_VISUAL_STEPS = [
    {'label': 'Pending', 'states': {'pending'}},
    {'label': 'Accepted', 'states': {'accepted', 'on_going_validation'}},
    {'label': 'In Progress', 'states': {'found_in_archive', 'in_process'}},
    {'label': 'Ready for Pickup', 'states': {'ready_for_pickup'}},
    {'label': 'Claimed', 'states': {'claimed'}},
]

PASSWORD_RESET_PENDING_OTP_ID_KEY = 'pending_password_reset_otp_id'
PASSWORD_RESET_AUTH_USER_ID_KEY = 'password_reset_auth_user_id'
PASSWORD_RESET_AUTH_EXPIRES_KEY = 'password_reset_auth_expires_at'


def _first_form_errors(form) -> dict[str, str]:
    return {field: messages[0] for field, messages in form.errors.items() if messages}


def _normalize_request_status(raw_status: str) -> str:
    status = (raw_status or '').strip().lower()
    status_map = {
        'booked': 'pending',
        'approved': 'accepted',
    }
    return status_map.get(status, status)


def _is_profile_complete(user: dict | None) -> bool:
    if not user:
        return False
    return all(
        [
            bool(str(user.get('graduated_program') or '').strip()),
            bool(str(user.get('year_graduated') or '').strip()),
            bool(str(user.get('address') or '').strip()),
        ]
    )


def _attach_progress_tracker(bookings: list[dict]) -> list[dict]:
    total_steps = len(REQUEST_PROGRESS_STEPS)
    for booking in bookings:
        normalized = _normalize_request_status(str(booking.get('status') or 'pending'))
        if normalized == 'rejected':
            booking['tracker_index'] = -1
            booking['tracker_visual_index'] = 0
            booking['tracker_percent'] = 0
            booking['tracker_state'] = 'rejected'
            booking['tracker_label'] = 'Rejected'
            continue

        if normalized not in REQUEST_PROGRESS_STEPS:
            normalized = 'pending'

        idx = REQUEST_PROGRESS_STEPS.index(normalized)
        booking['tracker_index'] = idx
        booking['tracker_percent'] = int(((idx + 1) / total_steps) * 100)
        booking['tracker_state'] = 'active'
        booking['tracker_label'] = REQUEST_PROGRESS_META[idx]['label']
        booking['tracker_visual_index'] = 0
        for visual_idx, visual_step in enumerate(TRACKER_VISUAL_STEPS):
            if normalized in visual_step['states']:
                booking['tracker_visual_index'] = visual_idx
                break

    return bookings


def _clear_password_reset_session() -> None:
    session.pop(PASSWORD_RESET_PENDING_OTP_ID_KEY, None)
    session.pop(PASSWORD_RESET_AUTH_USER_ID_KEY, None)
    session.pop(PASSWORD_RESET_AUTH_EXPIRES_KEY, None)


def _format_iso_date_long(value: str) -> str:
    raw = (value or '').strip()
    if not raw:
        return ''
    try:
        return date.fromisoformat(raw).strftime('%B %d, %Y')
    except ValueError:
        return raw


def _build_claim_slip_pdf_bytes(form_data: dict) -> bytes:
    css_path = Path(app.root_path) / 'static' / 'css' / 'admin_claim_slip.css'
    logo_path = Path(app.root_path) / 'static' / 'images' / 'logo_main.png'
    with css_path.open('r', encoding='utf-8') as css_file:
        inline_css = css_file.read()
    logo_data_uri = ''
    if logo_path.exists():
        logo_bytes = logo_path.read_bytes()
        logo_data_uri = f"data:image/png;base64,{base64.b64encode(logo_bytes).decode('ascii')}"

    pdf_html = render_template(
        'admin/claim_slip_pdf.html',
        form_data=form_data,
        inline_css=inline_css,
        logo_src=logo_data_uri,
    )

    # Primary renderer: Chromium print engine (best CSS fidelity for this slip layout).
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(pdf_html, wait_until='load')
            page.emulate_media(media='print')
            pdf_bytes = page.pdf(
                format='A4',
                landscape=True,
                print_background=True,
                margin={
                    'top': '4mm',
                    'right': '4mm',
                    'bottom': '4mm',
                    'left': '4mm',
                },
            )
            browser.close()
            if pdf_bytes:
                return pdf_bytes
    except Exception:
        pass

    # Fallback renderer for environments where Chromium is unavailable.
    try:
        import io
        from xhtml2pdf import pisa

        output = io.BytesIO()
        pdf_status = pisa.CreatePDF(src=pdf_html, dest=output)
        if not pdf_status.err:
            return output.getvalue()
    except Exception:
        pass

    try:
        import importlib

        weasyprint_module = importlib.import_module('weasyprint')
        html_class = getattr(weasyprint_module, 'HTML', None)
        if html_class is None:
            raise RuntimeError('PDF renderer is unavailable. Install the "weasyprint" package first.')
        return html_class(string=pdf_html, base_url=request.url_root).write_pdf()
    except Exception as exc:  # pragma: no cover - environment-specific dependency load
        try:
            import io
            from reportlab.lib.pagesizes import landscape, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
            from reportlab.lib import colors

            output = io.BytesIO()
            doc = SimpleDocTemplate(
                output,
                pagesize=landscape(A4),
                leftMargin=8 * mm,
                rightMargin=8 * mm,
                topMargin=8 * mm,
                bottomMargin=8 * mm,
            )
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'ClaimSlipTitle',
                parent=styles['Title'],
                fontName='Helvetica-Bold',
                fontSize=18,
                leading=22,
                textColor=colors.HexColor('#0a4336'),
                spaceAfter=8,
            )
            header_style = ParagraphStyle(
                'ClaimSlipHeader',
                parent=styles['Heading2'],
                fontName='Helvetica-Bold',
                fontSize=11,
                leading=13,
                spaceAfter=4,
                textColor=colors.black,
            )
            body_style = ParagraphStyle(
                'ClaimSlipBody',
                parent=styles['BodyText'],
                fontName='Helvetica',
                fontSize=9,
                leading=11,
                spaceAfter=2,
            )
            small_style = ParagraphStyle(
                'ClaimSlipSmall',
                parent=styles['BodyText'],
                fontName='Helvetica',
                fontSize=8,
                leading=10,
                spaceAfter=2,
            )

            full_name = str(form_data.get('student_full_name') or '').strip() or 'Student'
            program_course = str(form_data.get('program_course') or '').strip() or 'N/A'
            date_of_request = str(form_data.get('date_of_request') or '').strip() or 'N/A'
            claim_date = str(form_data.get('claim_date') or '').strip() or 'N/A'
            reference_code = str(form_data.get('reference_code') or '').strip() or 'DRN'

            elements = [
                Paragraph('CLAIM SLIP', title_style),
                Paragraph(f'<b>Reference No:</b> {reference_code}', body_style),
                Paragraph(f'<b>Name of Student:</b> {full_name}', body_style),
                Paragraph(f'<b>Program/Course:</b> {program_course}', body_style),
                Paragraph(f'<b>Date of Request:</b> {date_of_request}', body_style),
                Paragraph(f'<b>Claim Date:</b> {claim_date}', body_style),
                Spacer(1, 4),
                Paragraph('Requirements To Bring', header_style),
            ]

            requirement_rows = []
            for key, label in [
                ('documentary_stamp', 'Documentary Stamp (1 stamp per document)'),
                ('school_id_valid_id', 'School ID / Any Valid ID'),
                ('psa_nso_or_affidavit', 'Original PSA/NSO, Marriage Certificate Affidavit or'),
                ('form_137', 'Form 137'),
                ('photo_2x2', '2x2 Picture w/ Nametag (RECENT PHOTO)'),
                ('transfer_credentials', 'Transfer Credentials (from previous school of attendance)'),
                ('police_clearance', 'Police Clearance'),
                ('medical_good_moral', 'Medical/Good Moral Certificate'),
            ]:
                checked = 'Yes' if key in (form_data.get('claim_requirements') or []) else 'No'
                requirement_rows.append([Paragraph(label, small_style), Paragraph(checked, small_style)])

            if requirement_rows:
                req_table = Table(requirement_rows, colWidths=[145 * mm, 20 * mm])
                req_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c7d7d1')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f8f6')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(req_table)

            elements.extend([
                Spacer(1, 6),
                Paragraph('This claim slip is generated from the request record. Please bring it together with the required supporting documents when claiming your request.', small_style),
            ])

            doc.build(elements)
            return output.getvalue()
        except Exception:
            raise RuntimeError('PDF renderer is unavailable. Install Playwright (with Chromium), xhtml2pdf, WeasyPrint, or use the built-in ReportLab fallback.') from exc


@app.before_request
def _load_user():
    load_current_user()


@app.context_processor
def inject_current_user():
    return {'current_user': getattr(g, 'current_user', None)}


@app.after_request
def add_security_headers(response):
    # Prevent browser/proxy caching for authenticated/sensitive pages.
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# ========================================
# ROUTES
# ========================================

# Home page - Document request landing page
@app.route('/')
def index():
    return render_template('public/index.html')


# Contact Us page
@app.route('/contact')
def contact():
    return render_template('public/contact.html')


# About Us page
@app.route('/about')
def about():
    return render_template('public/about.html')


# Unified login for student and admin users.
@app.route('/login', methods=['GET', 'POST'])
def login():
    errors = {}
    form_data = {'email': ''}
    form = LoginForm(request.form if request.method == 'POST' else None)

    if request.method == 'POST':
        email = (form.email.data or '').strip()
        password = form.password.data or ''
        remember = bool(form.remember.data)
        form_data['email'] = email

        if not form.validate():
            errors = _first_form_errors(form)
            flash('Please fix the highlighted fields and try again.', 'warning')
            return render_template('student_portal/login.html', errors=errors, form_data=form_data)

        user = authenticate_user(email, password)
        if not user:
            errors['auth'] = 'Invalid email or password.'
            flash('Invalid credentials. Please try again.', 'danger')
            return render_template('student_portal/login.html', errors=errors, form_data=form_data)

        login_user(user, remember=remember)
        if 'admin' in user.get('roles', []):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_home'))

    return render_template('student_portal/login.html', errors=errors, form_data=form_data)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    current_user = getattr(g, 'current_user', None)
    if current_user and 'admin' in current_user.get('roles', []):
        return redirect(url_for('index'))

    _clear_password_reset_session()

    form = ForgotPasswordRequestForm(request.form if request.method == 'POST' else None)
    errors = {}
    form_data = {'email': ''}

    if request.method == 'POST':
        email = (form.email.data or '').strip().lower()
        form_data['email'] = email

        if not form.validate():
            errors = _first_form_errors(form)
            flash('Please enter a valid email address.', 'warning')
            return render_template(
                'student_portal/forgot_password.html',
                step='request_email',
                errors=errors,
                form_data=form_data,
            )

        role_flags = get_user_role_flags_by_email(email)
        if role_flags and role_flags.get('is_admin'):
            return redirect(url_for('index'))

        if role_flags and role_flags.get('is_student') and role_flags.get('is_active'):
            otp_code = generate_otp_code()
            otp_hash = generate_password_hash(otp_code, method='pbkdf2:sha256')
            reset_otp_id = create_password_reset_otp(
                user_id=int(role_flags['id']),
                email=email,
                otp_hash=otp_hash,
                expiry_minutes=app.config['PASSWORD_RESET_OTP_EXPIRY_MINUTES'],
            )
            try:
                send_password_reset_otp_email(
                    email,
                    otp_code,
                    app.config['PASSWORD_RESET_OTP_EXPIRY_MINUTES'],
                )
            except Exception:
                app.logger.exception('Password reset OTP email failed.')
                flash('Unable to send OTP right now. Please try again in a few minutes.', 'danger')
                return render_template(
                    'student_portal/forgot_password.html',
                    step='request_email',
                    errors=errors,
                    form_data=form_data,
                )

            session[PASSWORD_RESET_PENDING_OTP_ID_KEY] = int(reset_otp_id)
            flash('OTP sent to your email. Please verify to continue.', 'success')
            return render_template(
                'student_portal/forgot_password.html',
                step='verify_otp',
                errors={},
                form_data={'email': email},
                otp_email=email,
            )

        flash('If this student account exists, an OTP has been sent.', 'info')

    return render_template(
        'student_portal/forgot_password.html',
        step='request_email',
        errors=errors,
        form_data=form_data,
    )


@app.route('/forgot-password/verify-otp', methods=['POST'])
def forgot_password_verify_otp():
    current_user = getattr(g, 'current_user', None)
    if current_user and 'admin' in current_user.get('roles', []):
        return redirect(url_for('index'))

    form = VerifyOtpForm(request.form)
    otp_value = (form.otp_code.data or '').strip()
    otp_id = session.get(PASSWORD_RESET_PENDING_OTP_ID_KEY)
    otp_email = (form.otp_email.data or '').strip().lower()

    if not otp_id:
        flash('Password reset session expired. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    if not form.validate():
        errors = _first_form_errors(form)
        flash('OTP must be exactly 6 digits.', 'warning')
        return render_template(
            'student_portal/forgot_password.html',
            step='verify_otp',
            errors=errors,
            form_data={'email': otp_email},
            otp_email=otp_email,
        )

    otp_record = get_password_reset_otp_by_id(int(otp_id))
    if not otp_record or otp_record['used_at']:
        _clear_password_reset_session()
        flash('OTP is no longer valid. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    if int(otp_record['attempts'] or 0) >= app.config['PASSWORD_RESET_MAX_ATTEMPTS']:
        _clear_password_reset_session()
        flash('OTP attempts exceeded. Please request a new OTP.', 'danger')
        return redirect(url_for('forgot_password'))

    expires_at = datetime.fromisoformat(otp_record['expires_at'])
    if datetime.utcnow() > expires_at:
        _clear_password_reset_session()
        flash('OTP expired. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    if not check_password_hash(otp_record['otp_hash'], otp_value):
        increment_password_reset_attempt(int(otp_id))
        flash('Invalid OTP. Please try again.', 'danger')
        return render_template(
            'student_portal/forgot_password.html',
            step='verify_otp',
            errors={'otp_code': 'Invalid OTP code.'},
            form_data={'email': otp_email},
            otp_email=otp_email,
        )

    mark_password_reset_otp_used(int(otp_id))
    session.pop(PASSWORD_RESET_PENDING_OTP_ID_KEY, None)
    session[PASSWORD_RESET_AUTH_USER_ID_KEY] = int(otp_record['user_id'])
    session[PASSWORD_RESET_AUTH_EXPIRES_KEY] = (
        datetime.utcnow() + timedelta(minutes=int(app.config['PASSWORD_RESET_AUTH_MINUTES']))
    ).isoformat(timespec='seconds')

    flash('OTP verified. You can now set your new password.', 'success')
    return redirect(url_for('forgot_password_reset'))


@app.route('/forgot-password/reset', methods=['GET', 'POST'])
def forgot_password_reset():
    current_user = getattr(g, 'current_user', None)
    if current_user and 'admin' in current_user.get('roles', []):
        return redirect(url_for('index'))

    auth_user_id = session.get(PASSWORD_RESET_AUTH_USER_ID_KEY)
    auth_expires_raw = session.get(PASSWORD_RESET_AUTH_EXPIRES_KEY)
    if not auth_user_id or not auth_expires_raw:
        _clear_password_reset_session()
        flash('Password reset session expired. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    try:
        auth_expires_at = datetime.fromisoformat(str(auth_expires_raw))
    except ValueError:
        _clear_password_reset_session()
        flash('Password reset session expired. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    if datetime.utcnow() > auth_expires_at:
        _clear_password_reset_session()
        flash('Password reset session expired. Please request a new OTP.', 'warning')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm(request.form if request.method == 'POST' else None)
    errors = {}
    if request.method == 'POST':
        if not form.validate():
            errors = _first_form_errors(form)
            flash('Please fix the password fields and try again.', 'warning')
        else:
            new_password = form.password.data or ''
            password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            ok = update_user_password_hash(int(auth_user_id), password_hash)
            _clear_password_reset_session()
            if ok:
                flash('Password reset successful. You can now sign in.', 'success')
                return redirect(url_for('login'))
            flash('Unable to reset password right now. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template(
        'student_portal/forgot_password.html',
        step='reset_password',
        errors=errors,
        form_data={},
    )


# Student registration with OTP email verification.
@app.route('/register', methods=['GET', 'POST'])
def register():
    errors = {}
    step = 'register'
    form_data = {
        'student_id': '',
        'first_name': '',
        'middle_name': '',
        'last_name': '',
        'suffix': '',
        'email': '',
    }
    form = StudentRegistrationForm(request.form if request.method == 'POST' else None)

    if request.method == 'POST':
        student_id = (form.student_id.data or '').strip()
        first_name = (form.first_name.data or '').strip()
        middle_name = (form.middle_name.data or '').strip()
        last_name = (form.last_name.data or '').strip()
        suffix = (form.suffix.data or '').strip()
        email = (form.email.data or '').strip().lower()
        password = form.password.data or ''

        form_data = {
            'student_id': student_id,
            'first_name': first_name,
            'middle_name': middle_name,
            'last_name': last_name,
            'suffix': suffix,
            'email': email,
        }

        if not form.validate():
            errors = _first_form_errors(form)

        if get_user_by_email(email):
            errors['email'] = 'Email is already registered.'

        if get_user_by_student_id(student_id):
            errors['student_id'] = 'Student ID is already registered.'

        if errors:
            flash('Please correct the form and try again.', 'warning')
            return render_template('student_portal/register.html', step=step, errors=errors, form_data=form_data)

        otp_code = generate_otp_code()
        payload = {
            'student_id': student_id,
            'first_name': first_name,
            'middle_name': middle_name,
            'last_name': last_name,
            'suffix': suffix,
            'email': email,
            'password_hash': generate_password_hash(password),
        }
        encrypted_payload = encrypt_json(payload)
        otp_hash = generate_password_hash(otp_code)
        otp_id = create_registration_otp(
            email=email,
            otp_hash=otp_hash,
            payload_encrypted=encrypted_payload,
            expiry_minutes=app.config['OTP_EXPIRY_MINUTES'],
        )

        try:
            send_registration_otp_email(email, otp_code, app.config['OTP_EXPIRY_MINUTES'])
        except Exception:
            app.logger.exception('OTP email sending failed during registration flow.')
            flash('Unable to send OTP right now. Please try again in a few minutes.', 'danger')
            return render_template('student_portal/register.html', step=step, errors=errors, form_data=form_data)

        session['pending_registration_id'] = otp_id

        step = 'verify_otp'
        flash('OTP sent. Please check your email and verify within 5 minutes.', 'success')
        return render_template(
            'student_portal/register.html',
            step=step,
            errors={},
            form_data=form_data,
            otp_email=email,
        )

    return render_template('student_portal/register.html', step=step, errors=errors, form_data=form_data)


# OTP verification for student registration.
@app.route('/register/verify-otp', methods=['POST'])
def verify_registration_otp():
    form = VerifyOtpForm(request.form)
    otp_value = (form.otp_code.data or '').strip()
    otp_id = session.get('pending_registration_id')
    otp_email = (form.otp_email.data or '').strip().lower()

    if not otp_id:
        flash('Registration session expired. Please register again.', 'warning')
        return redirect(url_for('register'))

    if not form.validate():
        errors = _first_form_errors(form)
        flash('OTP must be exactly 6 digits.', 'warning')
        return render_template(
            'student_portal/register.html',
            step='verify_otp',
            errors=errors,
            form_data={'email': otp_email},
            otp_email=otp_email,
        )

    otp_record = get_registration_otp_by_id(int(otp_id))
    if not otp_record or otp_record['used_at']:
        flash('OTP is no longer valid. Please register again.', 'warning')
        session.pop('pending_registration_id', None)
        return redirect(url_for('register'))

    if otp_record['attempts'] >= app.config['OTP_MAX_ATTEMPTS']:
        flash('OTP attempts exceeded. Please register again.', 'danger')
        session.pop('pending_registration_id', None)
        return redirect(url_for('register'))

    expires_at = datetime.fromisoformat(otp_record['expires_at'])
    if datetime.utcnow() > expires_at:
        flash('OTP expired. Please register again.', 'warning')
        session.pop('pending_registration_id', None)
        return redirect(url_for('register'))

    if not check_password_hash(otp_record['otp_hash'], otp_value):
        increment_registration_attempt(int(otp_id))
        flash('Invalid OTP. Please try again.', 'danger')
        return render_template(
            'student_portal/register.html',
            step='verify_otp',
            errors={'otp_code': 'Invalid OTP code.'},
            form_data={'email': otp_email},
            otp_email=otp_email,
        )

    payload = decrypt_json(otp_record['payload_encrypted'])
    try:
        user_id = create_student_user(
            student_id=payload['student_id'],
            first_name=payload['first_name'],
            middle_name=payload['middle_name'],
            last_name=payload['last_name'],
            suffix=payload.get('suffix', ''),
            email=payload['email'],
            password_hash=payload['password_hash'],
        )
    except sqlite3.IntegrityError:
        session.pop('pending_registration_id', None)
        flash('Account already exists for this email or student ID.', 'warning')
        return redirect(url_for('login'))
    assign_role(user_id, 'student')
    mark_registration_otp_used(int(otp_id))
    session.pop('pending_registration_id', None)

    user = get_user_by_id(user_id)
    login_user(user, remember=False)
    flash('Registration complete. Welcome to your dashboard.', 'success')
    return redirect(url_for('student_dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been signed out.', 'info')
    return redirect(url_for('index'))


@app.route('/student/home')
@login_required
@role_required('student')
def student_home():
    return render_template('student_portal/home.html')


@app.route('/student/request-form-sample')
@login_required
@role_required('student')
def student_request_form_sample():
    return render_template('student_portal/request_form_sample.html')


@app.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    now = datetime.now()
    selected_year = int(request.args.get('year', now.year))
    selected_month = int(request.args.get('month', now.month))

    document_types = get_document_types_for_student()
    upcoming_slots = get_upcoming_appointment_slots(limit=20)
    slot_map = get_appointment_slots_by_month(selected_year, selected_month)
    month_weeks = calendar.Calendar(firstweekday=6).monthdayscalendar(selected_year, selected_month)
    selected_month_name = datetime(selected_year, selected_month, 1).strftime('%B').upper()

    prev_month = selected_month - 1
    prev_year = selected_year
    if prev_month < 1:
        prev_month = 12
        prev_year -= 1

    next_month = selected_month + 1
    next_year = selected_year
    if next_month > 12:
        next_month = 1
        next_year += 1

    booking_form = AppointmentBookingForm()
    regular_docs = [doc for doc in document_types if not bool(doc.get('is_ctc_service'))]
    ctc_service_docs = [doc for doc in document_types if bool(doc.get('is_ctc_service'))]
    booking_form.document_type_ids.choices = [
        (int(doc['id']), f"{doc['name']} (PHP {float(doc.get('price') or 0):.2f})")
        for doc in regular_docs
    ]
    student_bookings = get_student_appointment_bookings(int(g.current_user['id']))
    student_bookings = _attach_progress_tracker(student_bookings)
    has_accepted_update = any((row.get('status') or '').lower() == 'accepted' for row in student_bookings)
    latest_rejection_message = None
    for row in student_bookings:
        if (row.get('status') or '').lower() == 'rejected' and (row.get('rejection_message') or '').strip():
            latest_rejection_message = (row.get('rejection_message') or '').strip()
            break
    today_iso = date.today().isoformat()

    cert_docs = [
        doc for doc in regular_docs
        if str(doc.get('category') or '').strip().lower() == 'certification'
    ]
    records_docs = [
        doc for doc in regular_docs
        if str(doc.get('category') or '').strip().lower() == 'credentials/record'
    ]
    auth_docs = [
        doc for doc in regular_docs
        if str(doc.get('category') or '').strip().lower() == 'authentication'
    ]
    profile_complete = _is_profile_complete(getattr(g, 'current_user', None))

    return render_template(
        'student_portal/dashboard.html',
        document_types=document_types,
        upcoming_slots=upcoming_slots,
        slot_map=slot_map,
        month_weeks=month_weeks,
        selected_month_name=selected_month_name,
        selected_year=selected_year,
        selected_month=selected_month,
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year,
        booking_form=booking_form,
        student_bookings=student_bookings,
        has_accepted_update=has_accepted_update,
        latest_rejection_message=latest_rejection_message,
        progress_steps=REQUEST_PROGRESS_META,
        tracker_visual_steps=TRACKER_VISUAL_STEPS,
        today_iso=today_iso,
        records_docs=records_docs,
        cert_docs=cert_docs,
        auth_docs=auth_docs,
        ctc_service_docs=ctc_service_docs,
        profile_complete=profile_complete,
    )


@app.route('/student/profile', methods=['GET', 'POST'])
@login_required
@role_required('student')
def student_profile():
    profile = get_student_profile(int(g.current_user['id']))
    if not profile:
        flash('Unable to load your profile right now.', 'warning')
        return redirect(url_for('student_dashboard'))

    form = StudentProfileForm(request.form if request.method == 'POST' else None)
    if request.method == 'GET':
        form.graduated_program.data = (profile.get('graduated_program') or '').strip()
        form.major.data = (profile.get('major') or '').strip()
        form.year_graduated.data = (profile.get('year_graduated') or '').strip()
        form.address.data = (profile.get('address') or '').strip()
    else:
        if form.validate():
            updated = update_student_profile(
                int(g.current_user['id']),
                form.graduated_program.data or '',
                form.major.data or '',
                form.year_graduated.data or '',
                form.address.data or '',
            )
            if updated:
                flash('Profile updated successfully. You can now request forms.', 'success')
                return redirect(url_for('student_profile'))
            flash('Unable to update profile. Please review your input.', 'warning')
        else:
            flash('Please complete the required profile field.', 'warning')

    refreshed = get_student_profile(int(g.current_user['id'])) or profile
    return render_template(
        'student_portal/profile.html',
        profile=refreshed,
        form=form,
        form_errors=_first_form_errors(form) if request.method == 'POST' else {},
        profile_complete=_is_profile_complete(refreshed),
    )


@app.route('/student/change-password', methods=['GET', 'POST'])
@login_required
@role_required('student')
def student_change_password():
    form = StudentChangePasswordForm(request.form if request.method == 'POST' else None)
    errors = {}

    if request.method == 'POST':
        current_password = form.current_password.data or ''
        new_password = form.new_password.data or ''

        if not form.validate():
            errors = _first_form_errors(form)
            flash('Please fix the password fields and try again.', 'warning')
        elif not verify_user_password(int(g.current_user['id']), current_password):
            errors['current_password'] = 'Current password is incorrect.'
            flash('Current password is incorrect.', 'danger')
        elif current_password == new_password:
            errors['new_password'] = 'New password must be different from current password.'
            flash('New password must be different from current password.', 'warning')
        else:
            password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            ok = update_user_password_hash(int(g.current_user['id']), password_hash)
            if ok:
                flash('Password changed successfully.', 'success')
                return redirect(url_for('student_profile'))
            flash('Unable to change password right now.', 'danger')

    return render_template('student_portal/change_password.html', errors=errors, form_data={})


@app.route('/student/progress')
@login_required
@role_required('student')
def student_progress():
    student_bookings = get_student_appointment_bookings(int(g.current_user['id']))
    student_bookings = _attach_progress_tracker(student_bookings)
    if not student_bookings:
        flash('No request found to track yet. Please submit a request first.', 'info')
        return redirect(url_for('student_dashboard'))

    selected_booking_id_raw = (request.args.get('track_booking_id') or '').strip()
    selected_reference_raw = (request.args.get('track_ref') or '').strip().lower()
    tracked_booking = student_bookings[0]
    tracked_booking_id = int(tracked_booking['id'])
    if selected_reference_raw:
        matched_by_reference = next(
            (
                row
                for row in student_bookings
                if str(row.get('reference_code') or '').strip().lower() == selected_reference_raw
            ),
            None,
        )
        if matched_by_reference:
            tracked_booking = matched_by_reference
            tracked_booking_id = int(matched_by_reference['id'])
    if selected_booking_id_raw.isdigit():
        selected_booking_id = int(selected_booking_id_raw)
        matched = next((row for row in student_bookings if int(row.get('id') or 0) == selected_booking_id), None)
        if matched:
            tracked_booking = matched
            tracked_booking_id = selected_booking_id

    admin_update_message = (tracked_booking.get('progress_note') or '').strip()
    if not admin_update_message:
        status_text = str(tracked_booking.get('status') or 'pending').replace('_', ' ').title()
        admin_update_message = f'Current status: {status_text}'
    progress_events = get_booking_progress_events(int(tracked_booking['id']))

    return render_template(
        'student_portal/progress.html',
        student_bookings=student_bookings,
        tracked_booking=tracked_booking,
        tracked_booking_id=tracked_booking_id,
        admin_update_message=admin_update_message,
        progress_events=progress_events,
        tracker_visual_steps=TRACKER_VISUAL_STEPS,
    )


@app.route('/student/appointment/book', methods=['POST'])
@login_required
@role_required('student')
def student_book_appointment():
    if not _is_profile_complete(getattr(g, 'current_user', None)):
        flash('Please complete your profile first before requesting forms.', 'warning')
        return redirect(url_for('student_profile'))

    form = AppointmentBookingForm(request.form)
    available_docs = get_document_types_for_student()
    form.document_type_ids.choices = [
        (int(doc['id']), doc['name'])
        for doc in available_docs
    ]

    if not form.validate():
        flash('Please complete date, purpose, and document selection.', 'warning')
        return redirect(url_for('student_dashboard'))

    slot_date = (form.slot_date.data or '').strip()
    selected_doc_ids = list(form.document_type_ids.data or [])
    purpose = (form.purpose.data or '').strip()
    ctc_mode = (request.form.get('ctc_mode') or 'none').strip().lower()
    ctc_external_label = (request.form.get('ctc_external_label') or '').strip()

    try:
        if datetime.strptime(slot_date, '%Y-%m-%d').date() < date.today():
            flash('Past dates are not allowed. Please select today or a future date.', 'warning')
            return redirect(url_for('student_dashboard'))
    except ValueError:
        flash('Invalid request date.', 'warning')
        return redirect(url_for('student_dashboard'))

    success, message = create_appointment_booking_atomic(
        slot_date,
        int(g.current_user['id']),
        selected_doc_ids,
        purpose,
        ctc_mode=ctc_mode,
        ctc_external_label=ctc_external_label,
    )
    flash(message, 'success' if success else 'warning')
    return redirect(url_for('student_dashboard'))


@app.route('/api/notifications/count')
@login_required
def notification_count_api():
    user_id = int(g.current_user['id'])
    return jsonify({'unread_count': get_notification_unread_count(user_id)})


@app.route('/api/notifications/list')
@login_required
def notification_list_api():
    user_id = int(g.current_user['id'])
    tab = (request.args.get('tab') or 'unread').strip().lower()
    is_read = tab == 'read'
    raw_limit = (request.args.get('limit') or '20').strip()
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 20

    items = get_notifications_for_user(user_id, is_read=is_read, limit=limit)
    return jsonify(
        {
            'tab': 'read' if is_read else 'unread',
            'items': items,
        }
    )


@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def notification_mark_read_api(notification_id: int):
    user_id = int(g.current_user['id'])
    ok = mark_notification_as_read(user_id, notification_id)
    return jsonify({'ok': ok}), 200 if ok else 404


@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def notification_mark_all_read_api():
    user_id = int(g.current_user['id'])
    updated = mark_all_notifications_as_read(user_id)
    return jsonify({'updated': updated})


@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    dashboard_data = get_admin_dashboard_metrics()
    return render_template('admin/dashboard.html', dashboard=dashboard_data)


@app.route('/admin/requests')
@login_required
@role_required('admin')
def admin_requests():
    status_filter = (request.args.get('status') or 'all').strip().lower()
    search = (request.args.get('q') or '').strip()
    rows = get_admin_requests(status_filter=status_filter, search=search)
    return render_template(
        'admin/requests.html',
        requests_rows=rows,
        status_filter=status_filter,
        search=search,
    )


@app.route('/admin/archive')
@login_required
@role_required('admin')
def admin_archive():
    search = (request.args.get('q') or '').strip()
    rows = get_admin_requests(status_filter='archive', search=search)
    return render_template(
        'admin/archive.html',
        requests_rows=rows,
        search=search,
    )


@app.route('/admin/archive/<int:booking_id>/request-form')
@login_required
@role_required('admin')
def admin_archive_request_form(booking_id: int):
    form_data = get_admin_request_form_data(booking_id)
    if not form_data:
        flash('Request not found.', 'warning')
        return redirect(url_for('admin_archive'))
    return render_template('admin/request_form_view.html', form_data=form_data)


@app.route('/admin/archive/claim-slip-blank')
@login_required
@role_required('admin')
def admin_archive_claim_slip_blank():
    return render_template('admin/claim_slip_blank.html')


@app.route('/admin/archive/<int:booking_id>/claim-slip')
@login_required
@role_required('admin')
def admin_archive_claim_slip(booking_id: int):
    form_data = get_admin_claim_slip_data(booking_id)
    if not form_data:
        flash('Request not found.', 'warning')
        return redirect(url_for('admin_archive'))
    current_status = str(form_data.get('status') or '').strip().lower()
    if current_status == 'rejected':
        flash('Claim slip is not available for rejected requests.', 'warning')
        return redirect(url_for('admin_archive'))
    return render_template('admin/claim_slip_blank.html', form_data=form_data)


@app.route('/admin/archive/<int:booking_id>/claim-slip/send-email', methods=['POST'])
@login_required
@role_required('admin')
def admin_archive_claim_slip_send_email(booking_id: int):
    form_data = get_admin_claim_slip_data(booking_id)
    if not form_data:
        flash('Request not found.', 'warning')
        return redirect(url_for('admin_archive'))

    current_status = str(form_data.get('status') or '').strip().lower()
    if current_status == 'rejected':
        flash('Claim slip is not available for rejected requests.', 'warning')
        return redirect(url_for('admin_archive'))

    claim_date_raw = (request.form.get('claim_date') or '').strip()
    claim_requirements = request.form.getlist('claim_requirements')
    try:
        claim_date_iso = date.fromisoformat(claim_date_raw).isoformat()
    except ValueError:
        flash('Please enter a valid claim date before sending.', 'warning')
        return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))

    if not update_booking_claim_details(booking_id, claim_date_iso, claim_requirements):
        flash('Unable to save claim details.', 'warning')
        return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))

    # Re-read after saving so the PDF and email use the latest claim details.
    form_data = get_admin_claim_slip_data(booking_id)
    if not form_data:
        flash('Request not found after saving claim details.', 'warning')
        return redirect(url_for('admin_archive'))

    student_email = (form_data.get('student_email') or '').strip()
    if not student_email:
        flash('Student email is missing for this request.', 'warning')
        return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))

    try:
        pdf_bytes = _build_claim_slip_pdf_bytes(form_data)
        send_claim_slip_email(
            to_email=student_email,
            student_name=str(form_data.get('student_full_name') or '').strip(),
            reference_code=str(form_data.get('reference_code') or '').strip(),
            claim_date=_format_iso_date_long(claim_date_iso),
            pdf_bytes=pdf_bytes,
        )
    except RuntimeError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))
    except Exception:
        app.logger.exception('Failed to send claim slip email.')
        flash('Unable to send claim slip email right now. Please try again.', 'danger')
        return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))

    flash('Claim slip emailed successfully to the student.', 'success')
    return redirect(url_for('admin_archive_claim_slip', booking_id=booking_id))


@app.route('/admin/requests/<int:booking_id>/status', methods=['POST'])
@login_required
@role_required('admin')
def admin_request_update_status(booking_id: int):
    new_status = (request.form.get('status') or '').strip().lower()
    rejection_message = (request.form.get('rejection_message') or '').strip()
    progress_note = (request.form.get('progress_note') or '').strip()

    if new_status == 'rejected' and len(rejection_message) < 10:
        flash('For rejected requests, please provide a clear message (at least 10 characters).', 'warning')
        status_filter = (request.form.get('status_filter') or 'all').strip().lower()
        search = (request.form.get('search') or '').strip()
        return_page = (request.form.get('return_page') or 'requests').strip().lower()
        if return_page == 'archive':
            return redirect(url_for('admin_archive', q=search))
        return redirect(url_for('admin_requests', status=status_filter, q=search))

    ok = update_booking_status(
        booking_id,
        new_status,
        rejection_message,
        progress_note,
        int(g.current_user['id']),
    )
    if ok:
        flash('Request status updated successfully.', 'success')
    else:
        flash('Unable to update request status.', 'warning')

    status_filter = (request.form.get('status_filter') or 'all').strip().lower()
    search = (request.form.get('search') or '').strip()
    return_page = (request.form.get('return_page') or 'requests').strip().lower()
    if return_page == 'archive':
        return redirect(url_for('admin_archive', q=search))
    return redirect(url_for('admin_requests', status=status_filter, q=search))


@app.route('/admin/appointment-slots', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_appointment_slots():
    now = datetime.now()
    selected_year = int(request.args.get('year', now.year))
    selected_month = int(request.args.get('month', now.month))
    today_iso = date.today().isoformat()

    form = AppointmentSlotForm(request.form if request.method == 'POST' else None)
    if request.method == 'POST':
        if form.validate():
            slot_date = (form.slot_date.data or '').strip()
            try:
                if datetime.strptime(slot_date, '%Y-%m-%d').date() < date.today():
                    flash('Past dates are not allowed for slot configuration.', 'warning')
                    return redirect(
                        url_for(
                            'admin_appointment_slots',
                            year=selected_year,
                            month=selected_month,
                        )
                    )
                set_appointment_slot(
                    slot_date=slot_date,
                    total_slots=int(form.total_slots.data or 0),
                    admin_user_id=int(g.current_user['id']),
                )
            except ValueError:
                flash('Past dates are not allowed for slot configuration.', 'warning')
                return redirect(
                    url_for(
                        'admin_appointment_slots',
                        year=selected_year,
                        month=selected_month,
                    )
                )

            flash('Appointment slot updated successfully.', 'success')
            return redirect(
                url_for(
                    'admin_appointment_slots',
                    year=selected_year,
                    month=selected_month,
                )
            )
        flash('Please fix slot configuration form.', 'warning')

    selected_month_name = datetime(selected_year, selected_month, 1).strftime('%B').upper()
    slot_map = get_appointment_slots_by_month(selected_year, selected_month)
    month_weeks = calendar.Calendar(firstweekday=6).monthdayscalendar(selected_year, selected_month)

    prev_month = selected_month - 1
    prev_year = selected_year
    if prev_month < 1:
        prev_month = 12
        prev_year -= 1

    next_month = selected_month + 1
    next_year = selected_year
    if next_month > 12:
        next_month = 1
        next_year += 1

    return render_template(
        'admin/appointment_slots.html',
        form=form,
        slot_map=slot_map,
        month_weeks=month_weeks,
        selected_month_name=selected_month_name,
        today_iso=today_iso,
        selected_year=selected_year,
        selected_month=selected_month,
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year,
    )


@app.route('/admin/document-types')
@login_required
@role_required('admin')
def admin_document_types():
    document_types = get_document_types()
    form = DocumentTypeForm()
    form.category.data = 'Certification'
    form.is_active.data = True
    form.single_request_only.data = False
    form.is_ctc_service.data = False
    return render_template('admin/document_types.html', document_types=document_types, form=form, edit_doc=None, form_errors={})


@app.route('/admin/document-types/add', methods=['POST'])
@login_required
@role_required('admin')
def admin_document_types_add():
    form = DocumentTypeForm(request.form)
    document_types = get_document_types()

    if not form.validate():
        flash('Please fix the highlighted fields.', 'warning')
        return render_template(
            'admin/document_types.html',
            document_types=document_types,
            form=form,
            edit_doc=None,
            form_errors=_first_form_errors(form),
        )

    existing = get_document_type_by_name((form.name.data or '').strip())
    if existing:
        flash('Document type name already exists.', 'warning')
        return render_template(
            'admin/document_types.html',
            document_types=document_types,
            form=form,
            edit_doc=None,
            form_errors={'name': 'Document type name already exists.'},
        )

    create_document_type(
        category=form.category.data or 'Certification',
        name=form.name.data or '',
        description=form.description.data or '',
        price=float(form.price.data),
        is_active=bool(form.is_active.data),
        single_request_only=bool(form.single_request_only.data),
        is_ctc_service=bool(form.is_ctc_service.data),
    )
    flash('Document type added successfully.', 'success')
    return redirect(url_for('admin_document_types'))


@app.route('/admin/document-types/<int:document_type_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_document_types_edit(document_type_id: int):
    edit_doc = get_document_type_by_id(document_type_id)
    if not edit_doc:
        flash('Document type not found.', 'warning')
        return redirect(url_for('admin_document_types'))

    form = DocumentTypeForm(request.form if request.method == 'POST' else None)
    document_types = get_document_types()

    if request.method == 'GET':
        form.category.data = edit_doc.get('category') or 'Certification'
        form.name.data = edit_doc['name']
        form.description.data = edit_doc.get('description') or ''
        form.price.data = edit_doc.get('price') or 0
        form.is_active.data = bool(edit_doc.get('is_active'))
        form.single_request_only.data = bool(edit_doc.get('single_request_only'))
        form.is_ctc_service.data = bool(edit_doc.get('is_ctc_service'))
        return render_template(
            'admin/document_types.html',
            document_types=document_types,
            form=form,
            edit_doc=edit_doc,
            form_errors={},
        )

    if not form.validate():
        flash('Please fix the highlighted fields.', 'warning')
        return render_template(
            'admin/document_types.html',
            document_types=document_types,
            form=form,
            edit_doc=edit_doc,
            form_errors=_first_form_errors(form),
        )

    existing = get_document_type_by_name((form.name.data or '').strip())
    if existing and existing['id'] != document_type_id:
        flash('Document type name already exists.', 'warning')
        return render_template(
            'admin/document_types.html',
            document_types=document_types,
            form=form,
            edit_doc=edit_doc,
            form_errors={'name': 'Document type name already exists.'},
        )

    update_document_type(
        document_type_id=document_type_id,
        category=form.category.data or 'Certification',
        name=form.name.data or '',
        description=form.description.data or '',
        price=float(form.price.data),
        is_active=bool(form.is_active.data),
        single_request_only=bool(form.single_request_only.data),
        is_ctc_service=bool(form.is_ctc_service.data),
    )
    flash('Document type updated successfully.', 'success')
    return redirect(url_for('admin_document_types'))


@app.route('/admin/document-types/<int:document_type_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def admin_document_types_delete(document_type_id: int):
    success, message = delete_document_type(document_type_id)
    flash(message, 'success' if success else 'warning')
    return redirect(url_for('admin_document_types'))


# ========================================
# ERROR HANDLERS
# ========================================

@app.errorhandler(404)
def page_not_found(e):
    # Handle 404 errors
    return render_template('public/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    # Handle 500 errors
    return render_template('public/500.html'), 500


# ========================================
# APP ENTRY POINT
# ========================================

if __name__ == '__main__':
    # Debug mode enabled for development
    app.run(debug=True, host='0.0.0.0', port=5000)
