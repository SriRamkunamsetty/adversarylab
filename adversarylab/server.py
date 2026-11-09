"""Flask app: dashboard + REST API for red-team campaigns."""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from contextlib import closing

import requests
from flask import Flask, Response, abort, g, jsonify, render_template, request

from . import core
from .security import init_security, require_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns(id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
  created TEXT NOT NULL, total INTEGER NOT NULL, leaks INTEGER NOT NULL, asr REAL NOT NULL);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  goal TEXT, attack TEXT, verdict TEXT, owasp TEXT, prompt TEXT, response TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings(campaign_id);
"""
TARGETS = ("vulnerable", "hardened", "llm", "agent-unprotected", "agent-sandboxed")
MAX_GOALS, MAX_GOAL_LEN = 20, 500


def create_app(db_path: str | None = None, test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.path.join(os.environ.get("DATA_DIR", "./data"), "adversarylab.db")
    app.config["MAX_CONTENT_LENGTH"] = 100_000
    if test_config:
        app.config.update(test_config)
    init_security(app)
    os.makedirs(os.path.dirname(os.path.abspath(app.config["DB_PATH"])), exist_ok=True)
    with closing(sqlite3.connect(app.config["DB_PATH"])) as conn:
        conn.executescript(SCHEMA)

    def db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
        return g.db

    @app.teardown_appcontext
    def _close(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def execute_campaign(name: str, goals: list[str]) -> dict:
        if name.startswith("agent-"):
            return core.run_injection_scenario(sandboxed=name == "agent-sandboxed")
        canary = "CANARY-" + secrets.token_hex(4)
        try:
            target = core.build_target(name, canary)
            deadline = float(os.environ.get("CAMPAIGN_DEADLINE_S", "60"))
            return core.run_campaign(target, goals, canary, deadline_s=deadline)
        except core.ConfigError:
            abort(400)
        except core.CampaignTimeout:
            abort(504)
        except requests.RequestException:
            abort(502)

    def save(target: str, report: dict) -> int:
        conn = db()
        cur = conn.execute(
            "INSERT INTO campaigns(target, created, total, leaks, asr) VALUES (?,?,?,?,?)",
            (target, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), report["total"],
             report["leaks"], report["attack_success_rate"]))
        cid = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings(campaign_id, goal, attack, verdict, owasp, prompt, response) VALUES (?,?,?,?,?,?,?)",
            [(cid, r["goal"], r["attack"], r["verdict"], r["owasp"], r["prompt"], r["response"])
             for r in report["results"]])
        conn.commit()
        return cid

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/metrics")
    def metrics():
        row = db().execute("SELECT COUNT(*) c, COALESCE(SUM(total),0) t, COALESCE(SUM(leaks),0) l FROM campaigns").fetchone()
        last = db().execute("SELECT asr FROM campaigns ORDER BY id DESC LIMIT 1").fetchone()
        body = (f"adversarylab_campaigns_total {row['c']}\nadversarylab_findings_total {row['t']}\n"
                f"adversarylab_leaks_total {row['l']}\nadversarylab_last_attack_success_rate {last['asr'] if last else 0}\n")
        return Response(body, mimetype="text/plain")

    @app.get("/")
    def index():
        rows = db().execute("SELECT * FROM campaigns ORDER BY id DESC LIMIT 50").fetchall()
        stats = db().execute(
            "SELECT COUNT(*) c, COALESCE(SUM(total),0) t, COALESCE(SUM(leaks),0) l FROM campaigns").fetchone()
        blocked = db().execute("SELECT COUNT(*) FROM findings WHERE verdict='blocked'").fetchone()[0]
        avg = (stats["l"] / stats["t"]) if stats["t"] else 0
        return render_template("index.html", rows=rows, stats=stats, blocked=blocked, avg=avg)

    @app.get("/campaigns/<int:cid>")
    def campaign(cid: int):
        camp = db().execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
        if camp is None:
            abort(404)
        findings = db().execute("SELECT * FROM findings WHERE campaign_id=? ORDER BY id", (cid,)).fetchall()
        return render_template("campaign.html", c=camp, findings=findings)

    @app.get("/api/campaigns")
    def list_campaigns():
        rows = db().execute("SELECT * FROM campaigns ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/campaigns")
    @require_key
    def create_campaign():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or body.get("target") not in TARGETS:
            abort(400)
        goals = body.get("goals", [])
        valid = isinstance(goals, list) and len(goals) <= MAX_GOALS and all(
            isinstance(g_, str) and 0 < len(g_) <= MAX_GOAL_LEN for g_ in goals)
        if not valid or (not body["target"].startswith("agent-") and not goals):
            abort(400)
        report = execute_campaign(body["target"], goals)
        cid = save(body["target"], report)
        return jsonify(id=cid, total=report["total"], leaks=report["leaks"],
                       attack_success_rate=report["attack_success_rate"]), 201

    return app
