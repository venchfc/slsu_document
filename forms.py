from wtforms import BooleanField, DecimalField, IntegerField, PasswordField, SelectField, SelectMultipleField, StringField
from wtforms.form import Form
from wtforms.validators import DataRequired, EqualTo, Length, NumberRange, Optional, Regexp


EMAIL_REGEX = r'[^@\s]+@[^@\s]+\.[^@\s]+'

DOCUMENT_CATEGORY_CHOICES = [
	('Certification', 'Certification'),
	('Credentials/record', 'Credentials/record'),
	('Authentication', 'Authentication'),
]


class LoginForm(Form):
	email = StringField(
		'Email',
		validators=[
			DataRequired(message='Email is required.'),
			Regexp(EMAIL_REGEX, message='Enter a valid email address.'),
		],
	)
	password = PasswordField(
		'Password',
		validators=[DataRequired(message='Password is required.')],
	)
	remember = BooleanField('Remember me')


class StudentRegistrationForm(Form):
	student_id = StringField(
		'Student ID',
		validators=[
			DataRequired(message='Student ID is required.'),
			Length(min=5, message='Student ID must be at least 5 characters.'),
		],
	)
	first_name = StringField(
		'First Name',
		validators=[DataRequired(message='First name is required.')],
	)
	middle_name = StringField(
		'Middle Name',
		validators=[DataRequired(message='Middle name is required.')],
	)
	last_name = StringField(
		'Last Name',
		validators=[DataRequired(message='Last name is required.')],
	)
	suffix = StringField('Suffix', validators=[Optional(), Length(max=20)])
	email = StringField(
		'Email',
		validators=[
			DataRequired(message='Email is required.'),
			Regexp(EMAIL_REGEX, message='Enter a valid email address.'),
		],
	)
	password = PasswordField(
		'Password',
		validators=[
			DataRequired(message='Password is required.'),
			Length(min=8, message='Password must be at least 8 characters.'),
		],
	)
	confirm_password = PasswordField(
		'Confirm Password',
		validators=[
			DataRequired(message='Please confirm your password.'),
			EqualTo('password', message='Passwords do not match.'),
		],
	)


class VerifyOtpForm(Form):
	otp_code = StringField(
		'OTP Code',
		validators=[
			DataRequired(message='OTP is required.'),
			Regexp(r'^\d{6}$', message='OTP must be exactly 6 digits.'),
		],
	)
	otp_email = StringField('Email', validators=[Optional()])


class ForgotPasswordRequestForm(Form):
	email = StringField(
		'Email',
		validators=[
			DataRequired(message='Email is required.'),
			Regexp(EMAIL_REGEX, message='Enter a valid email address.'),
		],
	)


class ResetPasswordForm(Form):
	password = PasswordField(
		'New Password',
		validators=[
			DataRequired(message='New password is required.'),
			Length(min=8, message='Password must be at least 8 characters.'),
		],
	)
	confirm_password = PasswordField(
		'Confirm New Password',
		validators=[
			DataRequired(message='Please confirm your new password.'),
			EqualTo('password', message='Passwords do not match.'),
		],
	)


class StudentChangePasswordForm(Form):
	current_password = PasswordField(
		'Current Password',
		validators=[DataRequired(message='Current password is required.')],
	)
	new_password = PasswordField(
		'New Password',
		validators=[
			DataRequired(message='New password is required.'),
			Length(min=8, message='Password must be at least 8 characters.'),
		],
	)
	confirm_new_password = PasswordField(
		'Confirm New Password',
		validators=[
			DataRequired(message='Please confirm your new password.'),
			EqualTo('new_password', message='Passwords do not match.'),
		],
	)


class DocumentTypeForm(Form):
	category = SelectField(
		'Category',
		choices=DOCUMENT_CATEGORY_CHOICES,
		validators=[DataRequired(message='Category is required.')],
	)
	name = StringField(
		'Document Name',
		validators=[
			DataRequired(message='Document name is required.'),
			Length(min=3, max=120, message='Document name must be 3 to 120 characters.'),
		],
	)
	description = StringField('Description', validators=[Optional(), Length(max=500)])
	price = DecimalField(
		'Price',
		validators=[
			DataRequired(message='Price is required.'),
			NumberRange(min=0, message='Price must be 0 or greater.'),
		],
	)
	is_active = BooleanField('Active')
	single_request_only = BooleanField('Single request only')
	is_ctc_service = BooleanField('Is CTC service')


class AppointmentSlotForm(Form):
	slot_date = StringField(
		'Slot Date',
		validators=[
			DataRequired(message='Date is required.'),
			Regexp(r'^\d{4}-\d{2}-\d{2}$', message='Date format must be YYYY-MM-DD.'),
		],
	)
	total_slots = IntegerField(
		'Total Slots',
		validators=[
			DataRequired(message='Daily slots is required.'),
			NumberRange(min=0, max=999, message='Daily slots must be between 0 and 999.'),
		],
	)


class AppointmentBookingForm(Form):
	slot_date = StringField(
		'Slot Date',
		validators=[
			DataRequired(message='Slot date is required.'),
			Regexp(r'^\d{4}-\d{2}-\d{2}$', message='Invalid slot date format.'),
		],
	)
	purpose = StringField(
		'Purpose',
		validators=[
			DataRequired(message='Purpose is required.'),
			Length(min=3, max=200, message='Purpose must be 3 to 200 characters.'),
		],
	)
	document_type_ids = SelectMultipleField(
		'Document Types',
		coerce=int,
		validators=[Optional()],
	)
	ctc_mode = StringField(
		'CTC Mode',
		validators=[Optional(), Regexp(r'^(none|external|apply_selected)$', message='Invalid CTC mode.')],
	)
	ctc_external_label = StringField(
		'CTC External Label',
		validators=[Optional(), Length(max=255, message='CTC label must not exceed 255 characters.')],
	)


class StudentProfileForm(Form):
	graduated_program = StringField(
		'Program Graduated',
		validators=[
			DataRequired(message='Program graduated is required.'),
			Length(min=3, max=150, message='Program graduated must be 3 to 150 characters.'),
		],
	)
	major = StringField(
		'Major',
		validators=[
			Optional(),
			Length(max=120, message='Major must not exceed 120 characters.'),
		],
	)
	year_graduated = StringField(
		'Year Graduated',
		validators=[
			DataRequired(message='Year graduated is required.'),
			Regexp(r'^\d{4}$', message='Year graduated must be a 4-digit year.'),
		],
	)
	address = StringField(
		'Address',
		validators=[
			DataRequired(message='Address is required.'),
			Length(min=8, max=255, message='Address must be 8 to 255 characters.'),
		],
	)

