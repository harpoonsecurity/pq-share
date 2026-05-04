import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from .config import settings


log = logging.getLogger(__name__)


def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = formataddr((settings.smtp_from_name, settings.smtp_from))
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if not settings.smtp_host:
        log.warning("SMTP not configured — printing email to stdout instead")
        print(f"=== EMAIL (no SMTP host) ===\nTo: {to}\nSubject: {subject}\n\n{body}\n=== END ===")
        return

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
        smtp.ehlo()
        if settings.smtp_use_starttls:
            smtp.starttls()
            smtp.ehlo()
        if settings.smtp_user and settings.smtp_password:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)
    log.info("sent email to=%s subject=%r via %s", to, subject, settings.smtp_host)
