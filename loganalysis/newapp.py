from flask import Flask, redirect, render_template_string, session, request, url_for
from confluent_kafka import Consumer, KafkaError
from collections import defaultdict
import threading
import json
import bcrypt

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "change-me-in-production"

USERNAME = "admin"
PASSWORD_HASH = b"$2b$12$qExTyQERVPQxBE3YYEKdoeVtyGEjkNo0WjGz/b.aDca.0jDbBmQyy"

KAFKA_BOOTSTRAP = "localhost:9092"

TOPICS = {
    "login_logs":            "User Login Events",
    "process_creation_logs": "Process Creation Events",
    "system_install_logs":   "Software Install Events",
    "user_create_logs":      "User Account Creation",
    "proc_login":            "Suspicious Process Logins",
    "geo_login":             "Suspicious Geolocation Alerts",
    "proc_exec":             "Suspicious Process Execution",
}

# Every log in these topics is treated as suspicious regardless of severity field
ALERT_TOPICS = {"proc_login", "geo_login", "proc_exec"}

MAX_CACHED  = 100   # logs kept per topic
POLL_TIMEOUT = 1.0  # seconds — blocks until a message arrives or timeout

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

cache: dict = defaultdict(list)
cache_lock = threading.Lock()


def is_suspicious(log, topic: str) -> bool:
    if topic in ALERT_TOPICS:
        return True
    if isinstance(log, dict):
        return log.get("severity") in ("high", "critical")
    return False


# ---------------------------------------------------------------------------
# Kafka worker — tight poll loop, no sleep
# ---------------------------------------------------------------------------

def kafka_worker():
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "dashboard-group",
        "auto.offset.reset": "latest",
    })
    consumer.subscribe(list(TOPICS.keys()))

    try:
        while True:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            if msg is None:
                continue

            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"[kafka] error: {msg.error()}")
                continue

            topic = msg.topic()

            try:
                value = json.loads(msg.value().decode("utf-8"))
            except Exception:
                value = msg.value().decode("utf-8", errors="replace")

            with cache_lock:
                cache[topic].append(value)
                if len(cache[topic]) > MAX_CACHED:
                    cache[topic] = cache[topic][-MAX_CACHED:]

    finally:
        consumer.close()


# ---------------------------------------------------------------------------
# Shared styles
# ---------------------------------------------------------------------------

BASE_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg:      #0d0f14;
    --surface: #141720;
    --border:  #1f2433;
    --muted:   #3a4060;
    --text:    #c8d0e8;
    --heading: #eef0f8;
    --accent:  #4f8ef7;
    --danger:  #f75d4f;
    --success: #3dd68c;
    --mono:    'JetBrains Mono', monospace;
    --display: 'Syne', sans-serif;
}

body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    min-height: 100vh;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.page { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }

.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 36px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
}
.wordmark {
    font-family: var(--display);
    font-size: 22px;
    font-weight: 800;
    color: var(--heading);
    letter-spacing: -0.03em;
}
.wordmark span { color: var(--accent); }

/* stat chips */
.chips { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 28px; }
.chip {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 18px;
}
.chip-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin-bottom: 4px;
}
.chip-value {
    font-size: 26px;
    font-weight: 600;
    color: var(--heading);
}
.chip.danger  .chip-value { color: var(--danger); }
.chip.success .chip-value { color: var(--success); }

/* topic cards */
.topic-list { display: flex; flex-direction: column; gap: 10px; }
.topic-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: border-color .15s;
}
.topic-card:hover { border-color: var(--accent); }
.topic-name {
    font-family: var(--display);
    font-size: 15px;
    font-weight: 700;
    color: var(--heading);
}
.badges { display: flex; gap: 8px; align-items: center; }
.badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
}
.badge.total { background: #1a2340; color: var(--accent); }
.badge.clean { background: #0e2a1f; color: var(--success); }
.badge.sus   { background: #2a1010; color: var(--danger); }

/* log table */
.log-table { width: 100%; border-collapse: collapse; }
.log-table th {
    text-align: left;
    padding: 10px 12px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
}
.log-table td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
.log-table tr:last-child td { border-bottom: none; }
.log-table tr.sus-row { background: rgba(247,93,79,.07); }
.log-table tr.sus-row td:first-child { border-left: 2px solid var(--danger); }

pre { white-space: pre-wrap; word-break: break-all; line-height: 1.6; }
.flag { color: var(--danger); font-weight: 600; font-size: 11px; }
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        # after
        password_input = request.form.get("password", "").encode()
        if request.form.get("username") == USERNAME and bcrypt.checkpw(password_input, PASSWORD_HASH):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."

    html = """<!doctype html><html><head><title>Login</title><style>
    """ + BASE_STYLE + """
    .login-wrap {
        display:flex; align-items:center; justify-content:center; min-height:100vh;
    }
    .login-box {
        background:var(--surface); border:1px solid var(--border);
        border-radius:12px; padding:40px; width:340px;
    }
    .login-box h1 {
        font-family:var(--display); font-size:20px; color:var(--heading); margin-bottom:28px;
    }
    .login-box h1 span { color:var(--accent); }
    label {
        display:block; font-size:11px; color:var(--muted);
        text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px;
    }
    input[type=text], input[type=password] {
        width:100%; background:var(--bg); border:1px solid var(--border);
        border-radius:6px; padding:10px 12px; color:var(--heading);
        font-family:var(--mono); font-size:13px; margin-bottom:18px;
    }
    input:focus { outline:none; border-color:var(--accent); }
    button {
        width:100%; background:var(--accent); color:#fff; border:none;
        border-radius:6px; padding:11px; font-family:var(--mono);
        font-size:13px; font-weight:600; cursor:pointer;
    }
    button:hover { opacity:.88; }
    .error { color:var(--danger); font-size:12px; margin-bottom:14px; }
    </style></head><body>
    <div class="login-wrap"><div class="login-box">
        <h1>Sec<span>Log</span></h1>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="POST">
            <label>Username</label>
            <input type="text" name="username" autocomplete="off" required>
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit">Sign in →</button>
        </form>
    </div></div>
    </body></html>"""

    return render_template_string(html, error=error)


@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    with cache_lock:
        topic_rows = []
        grand_total = 0
        grand_sus   = 0
        for tid, tname in TOPICS.items():
            logs  = cache.get(tid, [])
            total = len(logs)
            sus   = sum(1 for l in logs if is_suspicious(l, tid))
            grand_total += total
            grand_sus   += sus
            topic_rows.append({"id": tid, "name": tname, "total": total, "sus": sus})

    html = """<!doctype html><html><head>
    <title>SecLog — Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>""" + BASE_STYLE + """</style></head><body>
    <div class="page">

        <div class="topbar">
            <div class="wordmark">Sec<span>Log</span></div>
            <a href="/login" style="font-size:12px;color:var(--muted);">sign out</a>
        </div>

        <div class="chips">
            <div class="chip">
                <div class="chip-label">Topics</div>
                <div class="chip-value">{{ topic_rows|length }}</div>
            </div>
            <div class="chip">
                <div class="chip-label">Cached Logs</div>
                <div class="chip-value">{{ grand_total }}</div>
            </div>
            <div class="chip {{ 'danger' if grand_sus > 0 else 'success' }}">
                <div class="chip-label">⚠ Suspicious</div>
                <div class="chip-value">{{ grand_sus }}</div>
            </div>
        </div>

        <div class="topic-list">
            {% for t in topic_rows %}
            <a href="/logs/{{ t.id }}" style="text-decoration:none;">
                <div class="topic-card">
                    <div class="topic-name">{{ t.name }}</div>
                    <div class="badges">
                        <span class="badge total">{{ t.total }} logs</span>
                        {% if t.sus > 0 %}
                            <span class="badge sus">{{ t.sus }} suspicious</span>
                        {% else %}
                            <span class="badge clean">✓ clean</span>
                        {% endif %}
                    </div>
                </div>
            </a>
            {% endfor %}
        </div>

    </div></body></html>"""

    return render_template_string(html, topic_rows=topic_rows,
                                  grand_total=grand_total, grand_sus=grand_sus)


@app.route("/logs/<topic>")
def logs(topic):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if topic not in TOPICS:
        return "Unknown topic", 404

    display_name = TOPICS[topic]

    with cache_lock:
        log_list = list(cache.get(topic, []))

    total     = len(log_list)
    sus_count = sum(1 for l in log_list if is_suspicious(l, topic))

    html = """<!doctype html><html><head>
    <title>{{ display_name }}</title>
    <meta http-equiv="refresh" content="3">
    <style>""" + BASE_STYLE + """</style></head><body>
    <div class="page">

        <div class="topbar">
            <div class="wordmark">Sec<span>Log</span></div>
            <a href="/" style="font-size:12px;color:var(--muted);">← Dashboard</a>
        </div>

        <h2 style="font-family:var(--display);font-size:20px;
                   color:var(--heading);margin-bottom:20px;">
            {{ display_name }}
        </h2>

        <div class="chips">
            <div class="chip">
                <div class="chip-label">Total Logs</div>
                <div class="chip-value">{{ total }}</div>
            </div>
            <div class="chip {{ 'danger' if sus_count > 0 else 'success' }}">
                <div class="chip-label">Suspicious</div>
                <div class="chip-value">{{ sus_count }}</div>
            </div>
            {% if total > 0 %}
            <div class="chip">
                <div class="chip-label">Suspicion Rate</div>
                <div class="chip-value">{{ "%.0f"|format(sus_count / total * 100) }}%</div>
            </div>
            {% endif %}
        </div>

        <table class="log-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Log Entry</th>
                    <th>Flag</th>
                </tr>
            </thead>
            <tbody>
                {% for log in log_list|reverse %}
                {% set s = is_suspicious(log, topic) %}
                <tr class="{{ 'sus-row' if s else '' }}">
                    <td style="color:var(--muted);white-space:nowrap;">{{ loop.index }}</td>
                    <td><pre>{{ log if log is string else log|tojson(indent=2) }}</pre></td>
                    <td>{% if s %}<span class="flag">⚠ SUSPICIOUS</span>{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

    </div></body></html>"""

    return render_template_string(
        html,
        display_name=display_name,
        topic=topic,
        log_list=log_list,
        total=total,
        sus_count=sus_count,
        is_suspicious=is_suspicious,
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    t = threading.Thread(target=kafka_worker, daemon=True)
    t.start()

    app.run(debug=True, port=5001, use_reloader=False)