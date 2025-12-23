import os
import requests
import smtplib
import sys
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

# ----------------------
# CONFIGURATION
# ----------------------
# Load from environment variables for security
OKTA_ORG_URL = os.getenv("OKTA_ORG_URL", "https://your-org.okta.com")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT")
ALERT_SENDER = os.getenv("ALERT_SENDER", SMTP_USERNAME)

if not OKTA_API_TOKEN:
    print("Error: OKTA_API_TOKEN environment variable is not set.", file=sys.stderr)
    sys.exit(1)

if not SMTP_USERNAME or not SMTP_PASSWORD:
    print("Warning: SMTP_USERNAME or SMTP_PASSWORD not set. Email alerts might fail.", file=sys.stderr)

# ----------------------
# EMAIL FUNCTION
# ----------------------
def send_email(subject, body):
    if not ALERT_RECIPIENT:
        print("Skipping email: ALERT_RECIPIENT not set.")
        print(f"Subject: {subject}")
        return

    msg = EmailMessage()
    msg["From"] = ALERT_SENDER
    msg["To"] = ALERT_RECIPIENT
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {ALERT_RECIPIENT}")
    except Exception as e:
        print(f"Failed to send email: {e}", file=sys.stderr)

# ----------------------
# OKTA LOG CHECK
# ----------------------
def check_user_deactivations():
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json"
    }

    # ISO 8601 format with Z for UTC is preferred by Okta
    since_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    params = {
        "filter": 'eventType eq "user.lifecycle.deactivate"',
        "since": since_time,
        "limit": 50
    }

    try:
        response = requests.get(
            f"{OKTA_ORG_URL}/api/v1/logs",
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()
        events = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching logs from Okta: {e}", file=sys.stderr)
        return

    if not events:
        print("No deactivations found in the last 5 minutes.")
        return

    for event in events:
        actor = event.get("actor", {})
        target = event.get("target", [{}])[0]

        admin = actor.get("alternateId", "Unknown admin")
        user = target.get("alternateId", "Unknown user")
        event_time = event.get("published")

        subject = f"Okta Alert: User Deactivated ({user})"
        body = (
            f"An Okta user has been deactivated.\n\n"
            f"User: {user}\n"
            f"Deactivated by: {admin}\n"
            f"Time: {event_time}\n"
        )
        
        # Log to console as well
        print(f"DETECTED: User {user} deactivated by {admin} at {event_time}")
        send_email(subject, body)

# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    print("Starting Okta Deactivation Check...")
    check_user_deactivations()