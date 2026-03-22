from flask import Flask, request, jsonify
import sqlite3
from datetime import date
from werkzeug.security import check_password_hash

app = Flask(__name__)
DB_NAME = "auth.db"

def get_db():
    return sqlite3.connect(DB_NAME)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    device_id = data.get("device_id", "").strip()

    if not username or not password or not device_id:
        return jsonify({"ok": False, "message": "Missing username, password, or device ID."}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, password_hash, active, expiry_date, device_id FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "message": "User not found."}), 401

    user_id, password_hash, active, expiry_date, saved_device_id = row

    if not active:
        conn.close()
        return jsonify({"ok": False, "message": "User is disabled."}), 403

    if not check_password_hash(password_hash, password):
        conn.close()
        return jsonify({"ok": False, "message": "Wrong password."}), 401

    if expiry_date:
        today = date.today().isoformat()
        if today > expiry_date:
            conn.close()
            return jsonify({"ok": False, "message": "Access expired."}), 403

    if not saved_device_id:
        cur.execute("UPDATE users SET device_id = ? WHERE id = ?", (device_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "message": "Login successful. Device registered."})

    if saved_device_id != device_id:
        conn.close()
        return jsonify({"ok": False, "message": "This user is locked to another computer."}), 403

    conn.close()
    return jsonify({"ok": True, "message": "Login successful."})

@app.route("/reset_device", methods=["POST"])
def reset_device():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET device_id = NULL WHERE username = ?", (username,))
    conn.commit()
    changed = cur.rowcount
    conn.close()

    if changed:
        return jsonify({"ok": True, "message": "Device reset done."})
    return jsonify({"ok": False, "message": "User not found."}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
