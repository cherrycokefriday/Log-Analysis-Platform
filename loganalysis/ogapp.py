from flask import Flask, jsonify, request, redirect, url_for, session
from confluent_kafka import Consumer, KafkaException, KafkaError
import threading
import time
import json
from flask import render_template_string

import os

DB_PATH = os.path.join(os.path.dirname(__file__), "logs.db")


import sqlite3

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

TOPIC_DISPLAY_NAMES = {
    "login_logs": "User Login Events",
    "process_creation_logs": "Process Creation Events",
    "system_install_logs": "Software Install Events",
    "user_create_logs": "User Account Creation",
    "proc_login": "Suspicious Process Logins",
    "geo_login": "Suspicious Geolocation Login Alerts",
    "proc_exec": "Suspicious Process Execution Alerts"
}


app = Flask(__name__)

app.secret_key = "itenbjedu8ba9(;B"

USERNAME = "admin"
PASSWORD = "password123"

from collections import defaultdict

TOPIC_CACHES = defaultdict(list)
cache_lock = threading.Lock()

KAFKA_CONFIG = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'security-log-group',
    'auto.offset.reset': 'latest'
}


def kafka_worker(poll_duration=5, sleep_interval=10):
    consumer = Consumer(KAFKA_CONFIG)
    consumer.subscribe(["login_logs",
                        "process_creation_logs",
                        "system_install_logs",
                        "user_create_logs",
                        "proc_login",
                        "geo_login",
                        "proc_exec",
                        ])

    msg = consumer.poll(0.5)
    print(msg)

    try:
        while True:
            print("polling kafka")

            start_time = time.time()

            # Poll Kafka for a limited duration
            while time.time() - start_time < poll_duration:
                msg = consumer.poll(timeout=0.5)

                if msg is None:
                    continue

                if msg.error():
                    # Handle error (ignore EOF events)
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        print(f"Kafka error: {msg.error()}")
                    continue

                try:
                    value = json.loads(msg.value().decode('utf-8'))
                    print(value)


                    # Extract timestamp (adjust depending on your log format)
                    timestamp = value.get("timestamp")

                    #is_incident = (
                     #   value.get("severity") in ["high", "critical"]
                    #)

                    if timestamp: #or is_incident:
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()

                        c.execute("INSERT INTO incidents (timestamp) VALUES (?)", (timestamp,))
                        conn.commit()
                        conn.close()

                except Exception:
                    value = msg.value().decode('utf-8')

                topic = msg.topic()

                with cache_lock:
                    TOPIC_CACHES[topic].append(value)
                    TOPIC_CACHES[topic] = TOPIC_CACHES[topic][-100:]

            # Pause before next polling cycle
            time.sleep(sleep_interval)


    finally:
        consumer.close()



@app.route("/logs/<topic>")
def get_logs(topic):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    display_name = TOPIC_DISPLAY_NAMES.get(topic, topic)
    
    with cache_lock:
        logs = list(TOPIC_CACHES.get(topic, []))

        html = """
    <html>
    <head>
        <title>{{ display_name }}</title>

        <meta http-equiv="refresh" content="3">

        <style>
            body {
                font-family: Arial;
                margin: 20px;
            }

            table {
                border-collapse: collapse;
                width: 100%;
            }

            th, td {
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
                vertical-align: top;
            }

            th {
                background-color: #f4f4f4;
            }

            tr:nth-child(even) {
                background-color: #fafafa;
            }

            pre {
                margin: 0;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
        </style>
    </head>

    <body>

        <h2>{{ display_name }}</h2>

        <a href="/">Back to Dashboard</a>

        <table>
            <tr>
                <th>#</th>
                <th>Log Data</th>
            </tr>

            {% for log in logs[::-1] %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><pre>{{ log }}</pre></td>
            </tr>
            {% endfor %}

        </table>

    </body>
    </html>
    """

    return render_template_string(
        html,
        logs=logs,
        topic=topic,
        display_name=display_name
    )

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        else:
            error = "Invalid username or password"

    html = """
    <html>
    <head>
        <title>Login</title>

        <style>
            body {
                font-family: Arial;
                background: #f4f4f4;
            }

            .login-box {
                width: 320px;
                margin: 100px auto;
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }

            input {
                width: 100%;
                padding: 10px;
                margin-top: 10px;
                margin-bottom: 15px;
            }

            button {
                width: 100%;
                padding: 10px;
                background: #007bff;
                color: white;
                border: none;
                cursor: pointer;
            }

            .error {
                color: red;
            }
        </style>
    </head>

    <body>

        <div class="login-box">

            <h2>Login</h2>

            {% if error %}
                <p class="error">{{ error }}</p>
            {% endif %}

            <form method="POST">

                <input type="text"
                       name="username"
                       placeholder="Username"
                       required>

                <input type="password"
                       name="password"
                       placeholder="Password"
                       required>

                <button type="submit">Login</button>

            </form>

        </div>

    </body>
    </html>
    """

    return render_template_string(html, error=error)



@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    with cache_lock:
        topics = []

        for topic in TOPIC_CACHES.keys():
            topics.append({
                "id": topic,
                "name": TOPIC_DISPLAY_NAMES.get(topic, topic)
            })

    html = """
    <html>
    <head>
        <title>Kafka Security Dashboard</title>

        <style>
            body {
                font-family: Arial;
                margin: 40px;
            }

            .topic {
                padding: 12px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 8px;
            }

            a {
                text-decoration: none;
                font-size: 18px;
            }
        </style>
    </head>

    <body>

        <h1>Kafka Topics</h1>

        {% for topic in topics %}
            <div class="topic">
                <a href="/logs/{{ topic.id }}">
                    {{ topic.name }}
                </a>
            </div>
        {% endfor %}

        <br>
        <a href="/graph">Incident Graph</a>

    </body>
    </html>
    """

    return render_template_string(html, topics=topics)

if __name__ == "__main__":
    init_db()

    t = threading.Thread(target=kafka_worker, daemon=True)
    t.start()

    app.run(debug=True, port=5001, use_reloader=False)




### to filter for incidents: 
# 