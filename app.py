import os
import hashlib
import smtplib
from email.message import EmailMessage
from flask import Flask, request, abort

app = Flask(__name__)

TRACK17_API_KEY = os.environ["TRACK17_API_KEY"]

# Outlook / GoDaddy (Microsoft 365) SMTP settings
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
ALERT_TO  = os.environ["ALERT_TO"]  # comma-separated list
FROM_EMAIL = os.environ.get("FROM_EMAIL", SMTP_USER)

BAD_MAIN = {"DeliveryFailure", "Exception"}
BAD_SUB = {
    "DeliveryFailure_Rejected",
    "DeliveryFailure_InvalidAddress",
    "DeliveryFailure_NoBody",
    "Exception_Returning",
    "Exception_Returned",
    "Exception_Rejected",
    "Exception_Lost",
    "Exception_Cancel",
}

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def is_bad(main_status: str | None, sub_status: str | None) -> bool:
    if main_status not in BAD_MAIN:
        return False
    # If you want alerts for ANY DeliveryFailure/Exception, replace with: return True
    return (sub_status or "") in BAD_SUB

def send_alert_email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)

@app.get("/")
def home():
    return "OK - 17TRACK alert webhook running", 200

@app.post("/webhook/17track")
def webhook_17track():
    raw_body = request.get_data(as_text=True)

    # 17TRACK signature: sha256("<raw_body>/<API_KEY>")
    received_sign = (request.headers.get("sign") or "").lower().strip()
    computed_sign = sha256_hex(f"{raw_body}/{TRACK17_API_KEY}")

    if not received_sign or received_sign != computed_sign:
        abort(401, "invalid signature")

    payload = request.get_json(silent=True) or {}
    if payload.get("event") != "TRACKING_UPDATED":
        return "ok", 200

    data = payload.get("data", {})
    tracking_number = data.get("number")

    latest = (((data.get("track_info") or {}).get("latest_status")) or {})
    main_status = latest.get("status")
    sub_status = latest.get("sub_status")

    if is_bad(main_status, sub_status):
        subject = f"🚨 Shipment issue: {tracking_number}"
        body = (
            f"Tracking: {tracking_number}\n"
            f"Main status: {main_status}\n"
            f"Sub status: {sub_status}\n\n"
            f"Latest status object:\n{latest}\n"
        )
        send_alert_email(subject, body)

    return "ok", 200