import base64
import json
import os
import re
import secrets
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

SMS_OTP_URL = "https://profile.swiggy.com/api/v3/app/sms_otp"
VERIFY_URL = "https://profile.swiggy.com/api/v3/app/login/verify"
USER_AGENT = "Swiggy-Android"

PENDING_OTP = {}

def new_device_id():
    return secrets.token_hex(16)

def login_headers(device_id=None):
    d = device_id or new_device_id()
    return {
        "Accept": "application/json; charset=utf-8",
        "app-version": "4.106.1",
        "category": "food",
        "deviceId": d,
        "swuid": d,
        "os-version": "9",
        "pl-version": "131",
        "User-Agent": USER_AGENT,
        "version-code": "1716",
        "x-channel": "swiggy",
    }

def _checked(r):
    try:
        d = r.json()
    except Exception:
        d = None
    if d is None:
        raise Exception(f"Non-JSON HTTP {r.status_code}")
    st = d.get("statusCode")
    if st == 999:
        raise Exception(f"Session expired: {d.get('statusMessage')}")
    if isinstance(st, int) and st != 0:
        raise Exception(f"API error {st}: {d.get('statusMessage')}")
    return d

def _jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

def _dig(d, *paths):
    for path in paths:
        cur = d
        ok = True
        for key in path.split("."):
            if isinstance(cur, dict) and key in cur and cur[key] not in (None, ""):
                cur = cur[key]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return None

def build_session(v):
    tid = _dig(v, "tid", "Tid", "data.tid", "headers.tid", "response.tid") or ""
    sid = _dig(v, "sid", "data.sid", "headers.sid") or ""
    token = _dig(v, "data.token", "data.accessToken", "token", "accessToken") or ""
    userid = _dig(v, "data.customer.userId", "data.customer.customerId", "data.userId", "userId", "user_id") or ""
    
    blob = json.dumps(v) if isinstance(v, dict) else ""
    if not tid:
        m = re.search(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+", blob)
        if m:
            tid = m.group(0)
    if not token:
        m = re.search(r"swiggy_at=([^;\s\"']+)", blob)
        if m:
            token = m.group(1)
    if not sid:
        m = re.search(r'"sid"\s*:\s*"([^"]+)"', blob) or re.search(r"[?&]sid=([^;&\s\"']+)", blob)
        if m:
            sid = m.group(1)
    if not userid and tid:
        userid = _jwt_payload(tid).get("user_id") or ""
    if not userid and token:
        userid = _jwt_payload(token).get("user_id") or ""
        
    return {"userid": str(userid) if userid else "", "tid": str(tid), "sid": str(sid), "token": str(token)}

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/api/send_otp", methods=["POST"])
def api_send_otp():
    data = request.json or {}
    mobile = str(data.get("mobile", "")).strip()[-10:]
    if len(mobile) != 10:
        return jsonify({"status": "error", "message": "10-digit mobile number required"}), 400
    
    device_id = new_device_id()
    try:
        with requests.Session() as s:
            r = s.get(f"{SMS_OTP_URL}?mobile={mobile}", headers=login_headers(device_id), timeout=30)
            res = _checked(r)
        
        PENDING_OTP[mobile] = {
            "tid": res.get("tid"),
            "sid": res.get("sid"),
            "device_id": device_id
        }
        return jsonify({"status": "success", "message": "OTP Sent successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/verify_otp", methods=["POST"])
def api_verify_otp():
    data = request.json or {}
    mobile = str(data.get("mobile", "")).strip()[-10:]
    otp = str(data.get("otp", "")).strip()
    
    st = PENDING_OTP.get(mobile)
    if not st:
        return jsonify({"status": "error", "message": "Session expired, please resend OTP"}), 400
    
    h = {
        **login_headers(st["device_id"]),
        "sid": st["sid"],
        "Tid": st["tid"],
        "Content-Type": "application/json; charset=utf-8"
    }
    p = {
        "cloningSignalsData": {
            "appFilesDirPathInvalid": 0, "developerModeEnabled": 0,
            "deviceModelVmos": 0, "emulatorStatus": 0,
            "packageName": "in.swiggy.android", "workProfileEnabled": 0
        },
        "otp": otp
    }
    
    try:
        with requests.Session() as s:
            r = s.post(f"{VERIFY_URL}?otp_source=Sms-automatic", headers=h, json=p, timeout=30)
            v = _checked(r)
            
        sess = build_session(v)
        data_dict = v.get("data", {}) if isinstance(v, dict) else {}
        
        result_obj = {
            "token": data_dict.get("token") or _dig(v, "data.token", "token") or sess.get("token", ""),
            "tid": v.get("tid") or _dig(v, "tid", "Tid") or sess.get("tid", ""),
            "sid": v.get("sid") or _dig(v, "sid") or sess.get("sid", ""),
            "deviceId": st["device_id"],
            "customerId": str(data_dict.get("customer_id") or data_dict.get("userId") or sess.get("userid", "")),
            "mobile": mobile
        }
        return jsonify({"status": "success", "data": result_obj})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
