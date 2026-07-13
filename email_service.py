import os
import ssl
import smtplib
from email.message import EmailMessage


def _read_smtp_config() -> dict:
    use_ssl = os.environ.get('SMTP_USE_SSL', '0').strip() == '1'
    timeout = int(os.environ.get('SMTP_TIMEOUT_SECONDS', '20'))

    config = {
        'host': os.environ.get('SMTP_HOST', '').strip(),
        'port': int(os.environ.get('SMTP_PORT', '465' if use_ssl else '587')),
        'username': os.environ.get('SMTP_USERNAME', '').strip(),
        'password': os.environ.get('SMTP_PASSWORD', '').replace(' ', '').strip(),
        'from_email': os.environ.get('SMTP_FROM_EMAIL', '').strip(),
        'use_ssl': use_ssl,
        'timeout': timeout,
    }

    required_keys = ('host', 'username', 'password', 'from_email')
    missing = [k for k in required_keys if not config[k]]
    if missing:
        missing_csv = ', '.join(missing)
        raise RuntimeError(f'Missing SMTP config in .env: {missing_csv}')

    return config


def _send_smtp_message(config: dict, message: EmailMessage) -> None:
    def send_with_ssl() -> None:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(config['host'], config['port'], timeout=config['timeout'], context=context) as smtp:
            smtp.login(config['username'], config['password'])
            smtp.send_message(message)

    def send_with_starttls() -> None:
        context = ssl.create_default_context()
        with smtplib.SMTP(config['host'], config['port'], timeout=config['timeout']) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(config['username'], config['password'])
            smtp.send_message(message)

    try:
        if config['use_ssl']:
            send_with_ssl()
        else:
            try:
                send_with_starttls()
            except (smtplib.SMTPException, OSError, TimeoutError, ValueError):
                send_with_ssl()
    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError('EMAIL SERVER FAILED. Check SMTP username/password or Gmail app password.') from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise RuntimeError('Unable to send email right now. Recipient address was rejected.') from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f'Unable to send email right now. SMTP error: {exc}') from exc
    except (OSError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f'Unable to send email right now. Connection error: {exc}') from exc


def _build_email_shell_html(content_html: str) -> str:
    return (
        '<html>'
        '<body style="margin:0;padding:0;background:#f3f6f8;font-family:Arial,Helvetica,sans-serif;color:#1e2329;">'
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:24px 12px;">'
        '<tr><td align="center">'
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:720px;background:#ffffff;border:1px solid #d9e1e7;border-radius:8px;overflow:hidden;">'
        '<tr><td style="background:#0a4336;color:#ffffff;padding:14px 20px;">'
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr>'
        '<td style="vertical-align:middle;">'
        '<div style="font-size:13px;letter-spacing:.3px;">SOUTHERN LUZON STATE UNIVERSITY</div>'
        '<div style="font-size:12px;opacity:.92;">Office of the University Registrar</div>'
        '</td>'
        '</tr>'
        '</table>'
        '</td></tr>'
        f'<tr><td style="padding:20px;">{content_html}</td></tr>'
        '<tr><td style="padding:14px 20px;background:#f6f8fa;border-top:1px solid #e1e7ec;color:#44515d;font-size:12px;line-height:1.5;">'
        '<strong>Office of the University Registrar</strong><br>'
        'Southern Luzon State University<br>'
        'Email: slsuregistrar@slsu.edu.ph | Tel: (042) 540-4763'
        '</td></tr>'
        '</table>'
        '</td></tr>'
        '</table>'
        '</body>'
        '</html>'
    )


def send_registration_otp_email(to_email: str, otp_code: str, expiry_minutes: int) -> None:
    config = _read_smtp_config()

    message = EmailMessage()
    message['Subject'] = 'SLSU Registration OTP Code'
    message['From'] = config['from_email']
    message['To'] = to_email
    message.set_content(
        (
            'SOUTHERN LUZON STATE UNIVERSITY\n'
            'Office of the University Registrar\n\n'
            'Good day!\n\n'
            'Your One-Time Password (OTP) for SLSU registration is:\n'
            f'{otp_code}\n\n'
            f'This code expires in {expiry_minutes} minutes.\n'
            'Do not share this code with anyone.\n\n'
            'If you did not request this OTP, please ignore this email or report it to the registrar office.\n'
        )
    )

    message.add_alternative(
        _build_email_shell_html(
            (
                '<p style="margin:0 0 12px;font-size:14px;">Good day,</p>'
                '<p style="margin:0 0 12px;font-size:14px;">Your One-Time Password (OTP) for <strong>SLSU registration</strong> is:</p>'
                '<div style="margin:14px 0;padding:12px;border:1px solid #d9e1e7;background:#f9fbfc;border-radius:6px;text-align:center;">'
                f'<div style="font-size:28px;letter-spacing:6px;font-weight:700;color:#0a4336;">{otp_code}</div>'
                '</div>'
                f'<p style="margin:0 0 12px;font-size:14px;">This code expires in <strong>{expiry_minutes} minutes</strong>. Do not share this code with anyone.</p>'
                '<div style="margin-top:14px;padding:12px;border:1px solid #f0d2d2;background:#fff6f6;border-radius:6px;">'
                '<div style="font-size:12px;font-weight:700;color:#7c1f1f;margin-bottom:6px;">SECURITY NOTICE</div>'
                '<div style="font-size:12px;line-height:1.5;color:#5a2020;">If you did not request this OTP, please ignore this email or report it to the registrar office immediately.</div>'
                '</div>'
            )
        ),
        subtype='html',
    )

    _send_smtp_message(config, message)


def send_password_reset_otp_email(to_email: str, otp_code: str, expiry_minutes: int) -> None:
    config = _read_smtp_config()

    message = EmailMessage()
    message['Subject'] = 'SLSU Password Reset OTP Code'
    message['From'] = config['from_email']
    message['To'] = to_email
    message.set_content(
        (
            'SOUTHERN LUZON STATE UNIVERSITY\n'
            'Office of the University Registrar\n\n'
            'Good day!\n\n'
            'Your One-Time Password (OTP) for SLSU password reset is:\n'
            f'{otp_code}\n\n'
            f'This code expires in {expiry_minutes} minutes.\n'
            'Do not share this code with anyone.\n\n'
            'If you did not request this OTP, please ignore this email or report it to the registrar office.\n'
        )
    )

    message.add_alternative(
        _build_email_shell_html(
            (
                '<p style="margin:0 0 12px;font-size:14px;">Good day,</p>'
                '<p style="margin:0 0 12px;font-size:14px;">Your One-Time Password (OTP) for <strong>SLSU password reset</strong> is:</p>'
                '<div style="margin:14px 0;padding:12px;border:1px solid #d9e1e7;background:#f9fbfc;border-radius:6px;text-align:center;">'
                f'<div style="font-size:28px;letter-spacing:6px;font-weight:700;color:#0a4336;">{otp_code}</div>'
                '</div>'
                f'<p style="margin:0 0 12px;font-size:14px;">This code expires in <strong>{expiry_minutes} minutes</strong>. Do not share this code with anyone.</p>'
                '<div style="margin-top:14px;padding:12px;border:1px solid #f0d2d2;background:#fff6f6;border-radius:6px;">'
                '<div style="font-size:12px;font-weight:700;color:#7c1f1f;margin-bottom:6px;">SECURITY NOTICE</div>'
                '<div style="font-size:12px;line-height:1.5;color:#5a2020;">If you did not request this OTP, please ignore this email or report it to the registrar office immediately.</div>'
                '</div>'
            )
        ),
        subtype='html',
    )

    _send_smtp_message(config, message)


def send_claim_slip_email(
    to_email: str,
    student_name: str,
    reference_code: str,
    claim_date: str,
    pdf_bytes: bytes,
) -> None:
    config = _read_smtp_config()
    recipient = (to_email or '').strip()
    if not recipient:
        raise RuntimeError('Recipient email is missing.')

    message = EmailMessage()
    message['Subject'] = f'SLSU Claim Slip - {reference_code or "DRN"}'
    message['From'] = config['from_email']
    message['To'] = recipient
    message.set_content(
        (
            'SOUTHERN LUZON STATE UNIVERSITY\n'
            'Office of the University Registrar\n\n'
            'Good day!\n\n'
            f'Please find attached the official claim slip for {student_name or "student"}.\n\n'
            'Claim Slip Details:\n'
            f'- Reference No: {reference_code or "N/A"}\n'
            f'- Claim Date: {claim_date or "N/A"}\n\n'
            'Please bring this claim slip together with the required supporting documents when claiming your request.\n\n'
            'DATA PRIVACY AND CONFIDENTIALITY NOTICE:\n'
            'This message and the attached document may contain personal and confidential information protected by data privacy laws. '
            'If you are not the intended recipient, please delete this email and its attachment immediately or report it to the university registrar/admin. '
            'Do not download, disclose, reproduce, resell, forward, copy, or use this document for any unauthorized or illegal purpose.\n\n'
            'Regards,\n'
            'Office of the University Registrar\n'
            'Southern Luzon State University\n'
            'Email: slsuregistrar@slsu.edu.ph | Tel: (042) 540-4763'
        )
    )

    message.add_alternative(
        _build_email_shell_html(
            (
                '<p style="margin:0 0 12px;font-size:14px;">Good day,</p>'
                f'<p style="margin:0 0 12px;font-size:14px;">Please find attached the official claim slip for <strong>{student_name or "student"}</strong>.</p>'
                '<div style="margin:14px 0;padding:12px;border:1px solid #d9e1e7;background:#f9fbfc;border-radius:6px;">'
                '<div style="font-size:13px;font-weight:700;margin-bottom:8px;">Claim Slip Details</div>'
                f'<div style="font-size:13px;line-height:1.5;"><strong>Reference No:</strong> {reference_code or "N/A"}<br><strong>Claim Date:</strong> {claim_date or "N/A"}</div>'
                '</div>'
                '<p style="margin:0 0 12px;font-size:14px;">Please bring this claim slip together with the required supporting documents when claiming your request.</p>'
                '<div style="margin-top:14px;padding:12px;border:1px solid #f0d2d2;background:#fff6f6;border-radius:6px;">'
                '<div style="font-size:12px;font-weight:700;color:#7c1f1f;margin-bottom:6px;">DATA PRIVACY AND CONFIDENTIALITY NOTICE</div>'
                '<div style="font-size:12px;line-height:1.5;color:#5a2020;">'
                'This message and the attached document may contain personal and confidential information protected by data privacy laws. '
                'If you are not the intended recipient, please delete this email and its attachment immediately or report it to the university registrar/admin. '
                'Do not download, disclose, reproduce, resell, forward, copy, or use this document for any unauthorized or illegal purpose.'
                '</div>'
                '</div>'
            )
        ),
        subtype='html',
    )

    filename = f'claim-slip-{(reference_code or "document").replace("/", "-")}.pdf'
    message.add_attachment(
        pdf_bytes,
        maintype='application',
        subtype='pdf',
        filename=filename,
    )

    _send_smtp_message(config, message)
