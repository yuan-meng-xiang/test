#!/usr/bin/env python3
import html
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "responses.jsonl"
ADMIN_CREDENTIALS_FILE = DATA_DIR / "admin_credentials.json"
ADMIN_INITIAL_PASSWORD_FILE = DATA_DIR / "admin_initial_password.txt"
SESSION_FILE = DATA_DIR / "admin_sessions.json"
SESSION_COOKIE = "survey_admin_session"
SESSION_SECONDS = 12 * 60 * 60
MAX_JSON_BYTES = 16 * 1024
QUESTION_IDS = [f"Q{i}" for i in range(1, 32)]
REQUIRED_FIELDS = QUESTION_IDS
RATE_BUCKETS = {}

QUESTION_TITLES = {
    'Q1': '在过去12个月内，您是否曾通过以下任一渠道，就您所居住社区或所在城市的公共服务事项，向政府部门提交过建议、投诉、咨询或求助？',
    'Q2': '那次您提交的事项属于以下哪种类型？',
    'Q3': '在上述您提交过的所有事项中，是否至少有一次收到了来自政府部门的正式回复（包括电话、短信、书面回函或线上平台回复）？',
    'Q4': '您反映的问题涉及哪个领域？',
    'Q5': '在您得到的政府工作人员回复中，是否明确提到了具体的责任办理单位（如某具体部门）？',
    'Q6': '该回复是否明确提到了反馈或办理的具体时间/期限？',
    'Q7': '该回复是否明确说明了如果没有按时完成，会有后续追踪或问责后果？',
    'Q8': '这条回复的篇幅/字数显得比较长。',
    'Q9': '为了回复您的意见，政府工作人员付出了很大的努力。',
    'Q10': '这条回复针对您提出的意见给出了很具体的说明。',
    'Q11': '这条回复的语气非常有礼貌，态度友善。',
    'Q12': '在现实生活中，政府工作人员给出这样的回复是非常真实、可信的。',
    'Q13': '有了这样的回复，政府工作人员会对自己处理意见的结果负责。',
    'Q14': '从回复来看，如果事情没办好，相关的政府部门或人员会受到追究。',
    'Q15': '这条回复让您清楚了后续处理流程的具体步骤。',
    'Q16': '整个处理过程对您而言是公开、明确的。',
    'Q17': '您的这次反馈能够有效推动政府改善相关工作。',
    'Q18': '像您这样的普通市民，有能力通过这种方式促进公共事务的解决。',
    'Q19': '您对这次政府回复服务的整体质量感到满意。',
    'Q20': '这种回复方式超出了您的预期。',
    'Q21': '如果将来再有类似的征求意见活动，您仍然非常愿意参与。',
    'Q22': '您会建议身边的朋友或家人也积极向政府反馈意见。',
    'Q23': '基于这次回复，您认为本地政府能够真正解决民众关心的问题。',
    'Q24': '您信任本地政府在做决策时会优先考虑公共利益。',
    'Q25': '您的年龄是：',
    'Q26': '您的性别：',
    'Q27': '您的受教育程度：',
    'Q28': '您目前的常住地属于：',
    'Q29': '在本次调查之前，您是否有过向政府或社区提建议、投诉或咨询的经历？',
    'Q30': '总的来说，您对政治或公共事务（如本地新闻、政府政策）的关注程度如何？',
    'Q31': '在参与本次调查之前，您对本地政府（区/县或街道）的整体信任程度如何？',
}


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    if not ADMIN_CREDENTIALS_FILE.exists():
        password = secrets.token_urlsafe(12)
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)
        credentials = {
            "username": "admin",
            "salt": salt,
            "password_hash": password_hash,
            "iterations": 260000,
        }
        ADMIN_CREDENTIALS_FILE.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
        ADMIN_INITIAL_PASSWORD_FILE.write_text(password + "\n", encoding="utf-8")
        os.chmod(ADMIN_CREDENTIALS_FILE, 0o600)
        os.chmod(ADMIN_INITIAL_PASSWORD_FILE, 0o600)


def hash_password(password, salt, iterations=260000):
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return digest.hex()


def read_credentials():
    ensure_data_dir()
    return json.loads(ADMIN_CREDENTIALS_FILE.read_text(encoding="utf-8"))


def valid_login(username, password):
    credentials = read_credentials()
    if not hmac.compare_digest(username, credentials["username"]):
        return False
    password_hash = hash_password(password, credentials["salt"], credentials.get("iterations", 260000))
    return hmac.compare_digest(password_hash, credentials["password_hash"])


def read_sessions():
    ensure_data_dir()
    if not SESSION_FILE.exists():
        return {}
    try:
        sessions = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    now = int(time.time())
    return {
        sid: item for sid, item in sessions.items()
        if isinstance(item, dict) and int(item.get("expires_at", 0)) > now
    }


def write_sessions(sessions):
    ensure_data_dir()
    SESSION_FILE.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
    os.chmod(SESSION_FILE, 0o600)


def create_session():
    sessions = read_sessions()
    sid = secrets.token_urlsafe(32)
    sessions[sid] = {"created_at": int(time.time()), "expires_at": int(time.time()) + SESSION_SECONDS}
    write_sessions(sessions)
    return sid


def delete_session(sid):
    sessions = read_sessions()
    if sid in sessions:
        del sessions[sid]
        write_sessions(sessions)


def read_rows():
    ensure_data_dir()
    if not DATA_FILE.exists():
        return []

    rows = []
    with DATA_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def append_row(row):
    ensure_data_dir()
    with DATA_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.chmod(DATA_FILE, 0o600)


def rate_limited(key, limit, window_seconds):
    now = time.time()
    bucket = [item for item in RATE_BUCKETS.get(key, []) if now - item < window_seconds]
    if len(bucket) >= limit:
        RATE_BUCKETS[key] = bucket
        return True
    bucket.append(now)
    RATE_BUCKETS[key] = bucket
    return False


def valid_response(payload):
    if not isinstance(payload, dict):
        return False, "invalid payload"

    missing = [field for field in REQUIRED_FIELDS if str(payload.get(field, "")).strip() == ""]
    if missing:
        return False, f"missing fields: {', '.join(missing[:3])}"

    allowed_values = {'Q1': ['1', '2', '3', '4'], 'Q2': ['1', '2', '3', '4'], 'Q3': ['1', '2'], 'Q4': ['1', '2', '3', '4', '5', '6'], 'Q5': ['1', '2', '3'], 'Q6': ['1', '2', '3'], 'Q7': ['1', '2', '3'], 'Q8': ['1', '2', '3', '4', '5'], 'Q9': ['1', '2', '3', '4', '5'], 'Q10': ['1', '2', '3', '4', '5'], 'Q11': ['1', '2', '3', '4', '5'], 'Q12': ['1', '2', '3', '4', '5'], 'Q13': ['1', '2', '3', '4', '5'], 'Q14': ['1', '2', '3', '4', '5'], 'Q15': ['1', '2', '3', '4', '5'], 'Q16': ['1', '2', '3', '4', '5'], 'Q17': ['1', '2', '3', '4', '5'], 'Q18': ['1', '2', '3', '4', '5'], 'Q19': ['1', '2', '3', '4', '5'], 'Q20': ['1', '2', '3', '4', '5'], 'Q21': ['1', '2', '3', '4', '5'], 'Q22': ['1', '2', '3', '4', '5'], 'Q23': ['1', '2', '3', '4', '5'], 'Q24': ['1', '2', '3', '4', '5'], 'Q25': ['1', '2'], 'Q26': ['1', '2'], 'Q27': ['1', '2'], 'Q28': ['1', '2'], 'Q29': ['1', '2'], 'Q30': ['1', '2', '3', '4', '5'], 'Q31': ['1', '2', '3', '4', '5']}
    for question_id, values in allowed_values.items():
        value = str(payload.get(question_id, "")).strip()
        if value not in values:
            return False, f"invalid {question_id}"

    return True, ""


def xls_bytes(rows):
    headers = ["submitted_at", *QUESTION_IDS]
    question_header = ["提交时间", *[f"{qid} {QUESTION_TITLES[qid]}" for qid in QUESTION_IDS]]
    table_rows = [question_header]
    table_rows.extend([[row.get(header, "") for header in headers] for row in rows])
    body = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in table_rows
    )
    document = f"""<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
<head><meta charset="utf-8"></head>
<body><table border="1">{body}</table></body>
</html>"""
    return ("\ufeff" + document).encode("utf-8")


class SurveyHandler(SimpleHTTPRequestHandler):
    server_version = "SurveyHTTP/1.0"

    def translate_path(self, path):
        parsed = urlparse(path)
        if parsed.path in {"/", "/admin", "/thanks"}:
            return str(BASE_DIR / "index.html")
        if parsed.path == "/favicon.ico":
            return str(BASE_DIR / "favicon.ico")
        return str(BASE_DIR / "__not_found__")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    def client_key(self, scope):
        forwarded = self.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",", 1)[0].strip() if forwarded else self.client_address[0]
        return f"{scope}:{ip}"

    def same_origin_request(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        expected = f"http://{self.headers.get('Host', '')}"
        return origin == expected

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_JSON_BYTES:
            return None, "request too large"
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")), ""
        except (ValueError, UnicodeDecodeError):
            return None, "invalid json"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/count":
            self.send_json({"count": len(read_rows())})
            return

        if parsed.path == "/api/me":
            self.send_json({"authenticated": self.authorized()})
            return

        if parsed.path == "/api/export":
            if not self.authorized():
                self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            payload = xls_bytes(read_rows())
            filename = "anonymous_survey_results_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".xls"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.ms-excel; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if parsed.path.startswith("/api/"):
            self.send_json({"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND)
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            if not self.same_origin_request():
                self.send_json({"ok": False, "error": "forbidden origin"}, HTTPStatus.FORBIDDEN)
                return
            if rate_limited(self.client_key("login"), 8, 10 * 60):
                self.send_json({"ok": False, "error": "too many attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
                return
            self.handle_login()
            return

        if parsed.path == "/api/logout":
            if not self.same_origin_request():
                self.send_json({"ok": False, "error": "forbidden origin"}, HTTPStatus.FORBIDDEN)
                return
            sid = self.session_id()
            if sid:
                delete_session(sid)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            body = json.dumps({"ok": True}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path != "/api/responses":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        if not self.same_origin_request():
            self.send_json({"ok": False, "error": "forbidden origin"}, HTTPStatus.FORBIDDEN)
            return

        if rate_limited(self.client_key("submit"), 40, 60):
            self.send_json({"ok": False, "error": "too many submissions"}, HTTPStatus.TOO_MANY_REQUESTS)
            return

        payload, error = self.read_json_body()
        if error:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if error == "request too large" else HTTPStatus.BAD_REQUEST
            self.send_json({"ok": False, "error": error}, status)
            return

        ok, error = valid_response(payload)
        if not ok:
            self.send_json({"ok": False, "error": error}, HTTPStatus.BAD_REQUEST)
            return

        row = {
            "submitted_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        }
        for question_id in QUESTION_IDS:
            row[question_id] = str(payload[question_id])

        append_row(row)
        self.send_json({"ok": True, "count": len(read_rows())}, HTTPStatus.CREATED)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/responses":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        if not self.same_origin_request():
            self.send_json({"ok": False, "error": "forbidden origin"}, HTTPStatus.FORBIDDEN)
            return

        if not self.authorized():
            self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        ensure_data_dir()
        if DATA_FILE.exists():
            backup = DATA_DIR / ("responses.deleted." + datetime.now().strftime("%Y%m%d_%H%M%S") + ".jsonl")
            DATA_FILE.rename(backup)
        self.send_json({"ok": True, "count": 0})

    def handle_login(self):
        payload, error = self.read_json_body()
        if error:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if error == "request too large" else HTTPStatus.BAD_REQUEST
            self.send_json({"ok": False, "error": error}, status)
            return

        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if not valid_login(username, password):
            time.sleep(0.25)
            self.send_json({"ok": False, "error": "invalid credentials"}, HTTPStatus.UNAUTHORIZED)
            return

        sid = create_session()
        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={sid}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Strict")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def session_id(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return value
        return ""

    def authorized(self):
        sid = self.session_id()
        if not sid:
            return False
        sessions = read_sessions()
        if sid not in sessions:
            return False
        sessions[sid]["expires_at"] = int(time.time()) + SESSION_SECONDS
        write_sessions(sessions)
        return True

    def send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ensure_data_dir()
    port = int(os.environ.get("PORT", "8899"))
    server = ThreadingHTTPServer(("0.0.0.0", port), SurveyHandler)
    print(f"Serving survey on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
