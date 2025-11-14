import threading
import time
import random
from collections import deque
from datetime import datetime
from flask import Flask, render_template, send_file, request, redirect, url_for
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import csv

app = Flask(__name__)

# ---- Demo config ----
AUTO_IMMUNE_ENABLED = True       # Set False to require manual blocking only
BLOCK_COOLDOWN_SEC = 20          # Minimum seconds between auto-block actions

# ---- Simulated / live state ----
traffic = deque(maxlen=300)  # packets/sec last N seconds
timestamps = deque(maxlen=300)
prediction = {"risk": 0.02, "eta": 60, "label": "stable", "countdown": None, "why": ""}
blocked = []  # list of dicts: {ip, time}
phish_alerts = []  # list of dicts: {from, subj, score, time}
cloak_on = True

# internal
lock = threading.Lock()
_last_block_ts = 0

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def init_series():
    now = time.time()
    base = 120 + int(random.random() * 80)
    for i in range(60):
        val = max(10, int(base + (random.random() - 0.5) * 30))
        traffic.append(val)
        timestamps.append(datetime.fromtimestamp(now - (59 - i)).strftime("%H:%M:%S"))

init_series()

# --- Replay helper (CICIDS CSV or simple CSV with value column) ---
def replay_csv_to_traffic(csv_path, speed_factor=1.0, loop=False):
    def _replay():
        print(f"[{now_ts()}] INFO Starting replay from {csv_path} speed={speed_factor} loop={loop}")
        while True:
            try:
                with open(csv_path, 'r') as fh:
                    reader = csv.reader(fh)
                    for row in reader:
                        if not row:
                            continue
                        try:
                            val = int(float(row[-1]))
                        except Exception:
                            continue
                        with lock:
                            traffic.append(max(0, val))
                            timestamps.append(datetime.now().strftime("%H:%M:%S"))
                        time.sleep(max(0.05, 1.0 / float(speed_factor)))
                if not loop:
                    break
            except Exception as e:
                print(f"[{now_ts()}] WARN Replay error: {e}")
                time.sleep(2)
                if not loop:
                    break
        print(f"[{now_ts()}] INFO Replay thread exiting for {csv_path}")
    t = threading.Thread(target=_replay, daemon=True)
    t.start()
    return t

# Simple heuristic phishing classifier
def classify_email_text(subject, body="", from_addr=""):
    score = 0.0
    if any(w in subject.lower() for w in ["urgent", "verify", "update", "payment", "reset"]):
        score += 0.45
    if "@" in from_addr and not from_addr.endswith("yourcompany.com"):
        score += 0.25
    if len(subject) < 30 and subject.isupper():
        score += 0.1
    return min(0.99, round(score, 2))

def explain_event(signals):
    reasons = []
    if signals.get("syn_ratio",0) > 1.5:
        reasons.append("SYN/ACK imbalance (possible SYN flood).")
    if signals.get("unique_src_growth",0) > 3:
        reasons.append("Rapid increase of unique source IPs.")
    if signals.get("burstiness",0) > 0.6:
        reasons.append("High packet burstiness and size variance.")
    if not reasons:
        reasons.append("Sequence matches low-confidence anomaly.")
    return " ".join(reasons)

def apply_auto_block_locked():
    global _last_block_ts
    now = time.time()
    # cooldown guard
    if not AUTO_IMMUNE_ENABLED:
        print(f"[{now_ts()}] INFO Auto-immune disabled; skipping auto-block.")
        return
    if (now - _last_block_ts) < BLOCK_COOLDOWN_SEC:
        # cooldown active, skip
        print(f"[{now_ts()}] INFO Auto-block skipped due to cooldown ({int(now - _last_block_ts)}s since last block).")
        return

    n = 2 + random.randint(0, 1)  # 2–3 IPs
    new_ips = []
    for _ in range(n):
        ip = f"192.168.{random.randint(0,255)}.{random.randint(10,250)}"
        blocked.insert(0, {"ip": ip, "time": datetime.now().strftime('%H:%M:%S')})
        new_ips.append(ip)
    del blocked[10:]  # keep last 10

    # single summary log (no spam)
    print(f"[{now_ts()}] [MOCK] Auto-blocked {len(new_ips)} IPs: {', '.join(new_ips)}")

    # traffic dip
    last = traffic[-1] if traffic else 100
    traffic.append(max(10, int(last * 0.35)))
    timestamps.append(datetime.now().strftime("%H:%M:%S"))

    # lower risk
    prediction.update({
        "risk": 0.03,
        "eta": 60,
        "label": "mitigated",
        "why": "Auto-block executed (cooldown-safe)."
    })

    _last_block_ts = now

def add_phish_locked():
    samples = [
        {"from": "ceo@acme-pay.com", "subj": "Urgent: Update Payment Details", "body": ""},
        {"from": "support@banking-sec.com", "subj": "Verify your account immediately", "body": ""},
        {"from": "it-helpdesk@company.local", "subj": "Password reset required", "body": ""},
    ]
    p = random.choice(samples).copy()
    p["time"] = datetime.now().strftime('%H:%M:%S')
    p["score"] = classify_email_text(p["subj"], p.get("body",""), p["from"])
    phish_alerts.insert(0, p)
    del phish_alerts[6:]
    print(f"[{now_ts()}] INFO Phish alert added: '{p['subj']}' from {p['from']} score={p['score']}")

# background generator: simulates regular traffic; triggers synthetic prediction bursts occasionally
def generator_loop():
    print(f"[{now_ts()}] INFO Background generator started")
    while True:
        time.sleep(1)
        with lock:
            last_val = traffic[-1] if traffic else 100
            noise = max(0, int(last_val + (random.random() - 0.45) * 40))
            traffic.append(noise)
            timestamps.append(datetime.now().strftime("%H:%M:%S"))

            # Occasionally trigger a prediction burst if not already counting down
            if prediction.get("countdown") is None and random.random() < 0.02:
                risk = round(0.5 + random.random() * 0.45, 2)
                signals = {
                    "syn_ratio": round(random.uniform(0.5, 3.5), 2),
                    "unique_src_growth": round(random.uniform(0.5, 6.0), 2),
                    "burstiness": round(random.uniform(0,1), 2)
                }
                why_text = explain_event(signals)
                prediction.update({
                    "risk": risk,
                    "eta": 15,
                    "label": "SYN-FLOOD" if risk > 0.7 else "DDoS-Proto",
                    "countdown": 15,
                    "why": why_text
                })
                print(f"[{now_ts()}] INFO Prediction triggered: risk={risk} label={prediction['label']} countdown=15s")

            # countdown tick
            if prediction.get("countdown") is not None:
                prediction["countdown"] -= 1
                if prediction["countdown"] <= 0:
                    apply_auto_block_locked()
                    prediction["countdown"] = None

            # Occasionally add phishing alert
            if random.random() < 0.03:
                add_phish_locked()

bg_thread = threading.Thread(target=generator_loop, daemon=True)
bg_thread.start()

@app.route("/")
def dashboard():
    with lock:
        state = {
            "prediction": prediction.copy(),
            "blocked": list(blocked),
            "phish": list(phish_alerts),
            "cloak_on": cloak_on,
            "now": datetime.now().strftime("%H:%M:%S"),
            "cloak_score": "0.22" if cloak_on else "0.91"
        }
    return render_template("dashboard.html", state=state)

@app.route("/chart/traffic.png")
def chart_traffic():
    with lock:
        x = list(timestamps)
        y = list(traffic)
    fig, ax = plt.subplots(figsize=(8, 3))
    ax.plot(range(len(y)), y, linewidth=1.6)
    ax.fill_between(range(len(y)), y, step='pre', alpha=0.15)
    if len(x) > 10:
        ticks = list(range(0, len(x), max(1, len(x)//10)))
        ax.set_xticks(ticks)
        ax.set_xticklabels([x[i] for i in ticks], rotation=45, fontsize=7)
    else:
        ax.set_xticklabels(x, rotation=45, fontsize=7)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("packets/sec")
    ax.set_title("Live Network Traffic")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    buf.seek(0)
    return send_file(buf, mimetype="image/png", max_age=0)

@app.route("/trigger_prediction", methods=["POST"])
def trigger_prediction():
    with lock:
        risk = round(0.5 + random.random() * 0.45, 2)
        signals = {
            "syn_ratio": round(random.uniform(0.5, 3.5), 2),
            "unique_src_growth": round(random.uniform(0.5, 6.0), 2),
            "burstiness": round(random.uniform(0,1), 2)
        }
        why_text = explain_event(signals)
        prediction.update({"risk": risk, "eta": 15, "label": "SYN-FLOOD" if risk > 0.7 else "DDoS-Proto", "countdown": 15, "why": why_text})
    print(f"[{now_ts()}] INFO Manual prediction triggered: risk={risk} label={prediction['label']} countdown=15s")
    return redirect(url_for("dashboard"))

@app.route("/force_block", methods=["POST"])
def force_block():
    with lock:
        apply_auto_block_locked()
        prediction["countdown"] = None
    return redirect(url_for("dashboard"))

@app.route("/add_phish", methods=["POST"])
def add_phish():
    with lock:
        add_phish_locked()
    return redirect(url_for("dashboard"))

@app.route("/toggle_cloak", methods=["POST"])
def toggle_cloak():
    global cloak_on
    with lock:
        cloak_on = not cloak_on
    print(f"[{now_ts()}] INFO Cloak toggled: now={'ON' if cloak_on else 'OFF'}")
    return redirect(url_for("dashboard"))

@app.route("/ack_phish/<int:index>", methods=["POST"])
def ack_phish(index):
    with lock:
        if 0 <= index < len(phish_alerts):
            removed = phish_alerts.pop(index)
            print(f"[{now_ts()}] INFO Phish quarantined: {removed['subj']} from {removed['from']}")
    return redirect(url_for("dashboard"))

@app.route("/unblock/<int:index>", methods=["POST"])
def unblock(index):
    with lock:
        if 0 <= index < len(blocked):
            removed = blocked.pop(index)
            print(f"[{now_ts()}] INFO Unblocked IP: {removed['ip']}")
    return redirect(url_for("dashboard"))

@app.route("/start_replay", methods=["POST"])
def start_replay():
    csv_path = request.form.get('path', 'sample_replay.csv')
    try:
        speed = float(request.form.get('speed', 1.0))
    except:
        speed = 1.0
    replay_csv_to_traffic(csv_path, speed_factor=speed, loop=True)
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    print(f"[{now_ts()}] INFO Starting Flask app")
    app.run(debug=True, host="0.0.0.0", port=8000)
