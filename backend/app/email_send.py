import logging
import re
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from .config import settings


log = logging.getLogger(__name__)


# CR / LF / NUL / other C0 control characters get replaced before any
# user-controlled value reaches a log sink. This prevents log-forging where
# an attacker injects a newline followed by a fake log entry.
_CONTROL_CHARS = re.compile(r"[\r\n\t\x00-\x1f\x7f]")


def _safe(value: str) -> str:
    """Strip control characters so user-supplied values can be logged inline."""
    return _CONTROL_CHARS.sub("?", value) if isinstance(value, str) else value


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
    log.info("sent email to=%r subject=%r via %s", _safe(to), _safe(subject), settings.smtp_host)
