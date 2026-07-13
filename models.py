from datetime import datetime

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), nullable=True, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=False)
    suffix = db.Column(db.String(20), nullable=True)
    graduated_program = db.Column(db.String(150), nullable=True)
    major = db.Column(db.String(120), nullable=True)
    year_graduated = db.Column(db.String(4), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    profile_completed = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"


class UserRole(db.Model):
    __tablename__ = 'user_roles'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), primary_key=True)

    def __repr__(self):
        return f"<UserRole user_id={self.user_id} role_id={self.role_id}>"


class DocumentType(db.Model):
    __tablename__ = 'document_types'

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(40), nullable=False, default='Certification')
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    single_request_only = db.Column(db.Boolean, nullable=False, default=False)
    is_ctc_service = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<DocumentType {self.name}>"


class RequestStatus(db.Model):
    __tablename__ = 'request_statuses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    display_order = db.Column(db.Integer, nullable=False, unique=True)

    def __repr__(self):
        return f"<RequestStatus {self.name}>"


class DocumentRequest(db.Model):
    __tablename__ = 'document_requests'

    id = db.Column(db.Integer, primary_key=True)
    request_code = db.Column(db.String(50), nullable=False, unique=True)
    requester_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    document_type_id = db.Column(db.Integer, db.ForeignKey('document_types.id', ondelete='RESTRICT'), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    current_status_id = db.Column(db.Integer, db.ForeignKey('request_statuses.id', ondelete='RESTRICT'), nullable=False)
    processed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<DocumentRequest {self.request_code}>"


class RequestStatusHistory(db.Model):
    __tablename__ = 'request_status_history'

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('document_requests.id', ondelete='CASCADE'), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('request_statuses.id', ondelete='RESTRICT'), nullable=False)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<RequestStatusHistory request_id={self.request_id} status_id={self.status_id}>"


class RegistrationOtp(db.Model):
    __tablename__ = 'registration_otps'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    payload_encrypted = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<RegistrationOtp {self.email}>"


class PasswordResetOtp(db.Model):
    __tablename__ = 'password_reset_otps'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<PasswordResetOtp {self.email}>"


class AppointmentSlot(db.Model):
    __tablename__ = 'appointment_slots'

    id = db.Column(db.Integer, primary_key=True)
    slot_date = db.Column(db.String(10), nullable=False, unique=True)
    total_slots = db.Column(db.Integer, nullable=False, default=0)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AppointmentBooking(db.Model):
    __tablename__ = 'appointment_bookings'

    id = db.Column(db.Integer, primary_key=True)
    reference_code = db.Column(db.String(32), nullable=True, unique=True)
    slot_id = db.Column(db.Integer, db.ForeignKey('appointment_slots.id', ondelete='CASCADE'), nullable=False)
    student_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    purpose = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='booked')
    ctc_mode = db.Column(db.String(20), nullable=False, default='none')
    ctc_external_label = db.Column(db.String(255), nullable=True)
    claim_date = db.Column(db.String(10), nullable=True)
    claim_requirements = db.Column(db.Text, nullable=True)
    progress_note = db.Column(db.Text, nullable=True)
    rejection_message = db.Column(db.Text, nullable=True)
    booked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AppointmentBookingDocument(db.Model):
    __tablename__ = 'appointment_booking_documents'

    booking_id = db.Column(db.Integer, db.ForeignKey('appointment_bookings.id', ondelete='CASCADE'), primary_key=True)
    document_type_id = db.Column(db.Integer, db.ForeignKey('document_types.id', ondelete='RESTRICT'), primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AppointmentBookingProgressEvent(db.Model):
    __tablename__ = 'appointment_booking_progress_events'

    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('appointment_bookings.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    progress_note = db.Column(db.Text, nullable=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    notification_type = db.Column(db.String(60), nullable=False)
    reference_code = db.Column(db.String(32), nullable=True)
    student_full_name = db.Column(db.String(220), nullable=True)
    message = db.Column(db.Text, nullable=False)
    related_booking_id = db.Column(db.Integer, db.ForeignKey('appointment_bookings.id', ondelete='SET NULL'), nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_at = db.Column(db.DateTime, nullable=True)
