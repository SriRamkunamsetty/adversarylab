"""Flask application: Dashboard, REST API, SARIF export, and Guardrails."""
from __future__ import annotations

import csv
import io
import os
import secrets
import sqlite3
import time

import requests
from flask import Flask, Response, abort, g, jsonify, render_template, request

from . import core
from .db import init_db
from .evaluators import generate_sarif_report, scan_pii_and_secrets
from .guardrails import AgentShield
from .owasp import OWASP_CATALOG
from .security import init_security, require_key

TARGETS = ("vulnerable", "hardened", "llm", "agent-unprotected", "agent-sandboxed")
MAX_GOALS, MAX_GOAL_LEN = 20, 500


def create_app(db_path: str | None = None, test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.path.join(os.environ.get("DATA_DIR", "./data"), "adversarylab.db")
    app.config["MAX_CONTENT_LENGTH"] = 100_000
    if test_config:
        app.config.update(test_config)
    init_security(app)

    # Initialize SQLite database with WAL mode and tables
    init_db(app.config["DB_PATH"])

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
            (
                target,
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                report["total"],
                report["leaks"],
                report["attack_success_rate"],
            ),
        )
        cid = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings(campaign_id, goal, attack, verdict, owasp, prompt, response) VALUES (?,?,?,?,?,?,?)",
            [
                (
                    cid,
                    r["goal"],
                    r["attack"],
                    r["verdict"],
                    r["owasp"],
                    r["prompt"],
                    r["response"],
                )
                for r in report["results"]
            ],
        )
        conn.commit()
        return cid

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        """Readiness probe for Kubernetes pod lifecycle."""
        try:
            db().execute("SELECT 1").fetchone()
            return jsonify(status="ready", database="connected")
        except Exception as e:
            return jsonify(status="not_ready", error=str(e)), 503

    @app.get("/metrics")
    def metrics():
        row = db().execute(
            "SELECT COUNT(*) c, COALESCE(SUM(total),0) t, COALESCE(SUM(leaks),0) l FROM campaigns"
        ).fetchone()
        last = db().execute("SELECT asr FROM campaigns ORDER BY id DESC LIMIT 1").fetchone()
        body = (
            f"# HELP adversarylab_campaigns_total Total red-team campaigns executed\n"
            f"# TYPE adversarylab_campaigns_total counter\n"
            f"adversarylab_campaigns_total {row['c']}\n"
            f"# HELP adversarylab_findings_total Total attack attempts evaluated\n"
            f"# TYPE adversarylab_findings_total counter\n"
            f"adversarylab_findings_total {row['t']}\n"
            f"# HELP adversarylab_leaks_total Total secret disclosures detected\n"
            f"# TYPE adversarylab_leaks_total counter\n"
            f"adversarylab_leaks_total {row['l']}\n"
            f"# HELP adversarylab_last_attack_success_rate Attack success rate of most recent campaign\n"
            f"# TYPE adversarylab_last_attack_success_rate gauge\n"
            f"adversarylab_last_attack_success_rate {last['asr'] if last else 0}\n"
        )
        return Response(body, mimetype="text/plain")

    @app.get("/")
    def index():
        rows = db().execute("SELECT * FROM campaigns ORDER BY id DESC LIMIT 50").fetchall()
        stats = db().execute(
            "SELECT COUNT(*) c, COALESCE(SUM(total),0) t, COALESCE(SUM(leaks),0) l FROM campaigns"
        ).fetchone()
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
            isinstance(g_, str) and 0 < len(g_) <= MAX_GOAL_LEN for g_ in goals
        )
        if not valid or (not body["target"].startswith("agent-") and not goals):
            abort(400)
        report = execute_campaign(body["target"], goals)
        cid = save(body["target"], report)
        return (
            jsonify(
                id=cid,
                total=report["total"],
                leaks=report["leaks"],
                attack_success_rate=report["attack_success_rate"],
            ),
            201,
        )

    @app.get("/api/campaigns/<int:cid>/sarif")
    def get_campaign_sarif(cid: int):
        """Export campaign findings in SARIF v2.1.0 format."""
        camp = db().execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
        if camp is None:
            abort(404)
        findings = db().execute("SELECT * FROM findings WHERE campaign_id=? ORDER BY id", (cid,)).fetchall()
        sarif_doc = generate_sarif_report(cid, camp["target"], [dict(f) for f in findings])
        return jsonify(sarif_doc)

    @app.get("/api/campaigns/<int:cid>/export")
    def export_campaign(cid: int):
        """Export campaign findings in CSV or JSON format."""
        camp = db().execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
        if camp is None:
            abort(404)
        findings = db().execute("SELECT * FROM findings WHERE campaign_id=? ORDER BY id", (cid,)).fetchall()
        fmt = request.args.get("format", "json").lower()

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["id", "goal", "attack", "verdict", "owasp", "prompt", "response"])
            for f in findings:
                writer.writerow([f["id"], f["goal"], f["attack"], f["verdict"], f["owasp"], f["prompt"], f["response"]])
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=campaign_{cid}.csv"},
            )

        return jsonify({
            "campaign": dict(camp),
            "findings": [dict(f) for f in findings],
        })

    @app.get("/api/owasp")
    def list_owasp():
        """Retrieve the OWASP Top 10 for LLM Applications (2025) catalog and active detections."""
        return jsonify({
            code: {
                "identifier": item.identifier,
                "name": item.name,
                "severity": item.severity.value,
                "description": item.description,
                "remediation": item.remediation,
            }
            for code, item in OWASP_CATALOG.items()
        })

    @app.post("/api/guardrails/scan")
    @require_key
    def guardrails_scan():
        """AgentShield Guardrail: Real-time inspection of inbound prompts and documents."""
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or "text" not in body or not isinstance(body["text"], str):
            abort(400)
        text = body["text"]
        inspection = AgentShield.inspect_prompt(text)
        pii = scan_pii_and_secrets(text)
        return jsonify({
            **inspection,
            "pii_and_secrets_detected": pii,
            "has_sensitive_data": bool(pii),
        })

    @app.get("/api/spec.json")
    def openapi_spec():
        """OpenAPI 3.0 specification for AdversaryLab."""
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "AdversaryLab API",
                "version": "0.1.0",
                "description": (
                    "Enterprise AI red-teaming platform mapped to OWASP LLM Top 10 (2025) "
                    "with AgentShield guardrails."
                ),
            },
            "paths": {
                "/healthz": {"get": {"summary": "Health check", "responses": {"200": {"description": "OK"}}}},
                "/readyz": {"get": {"summary": "Readiness probe", "responses": {"200": {"description": "Ready"}}}},
                "/metrics": {"get": {"summary": "Prometheus metrics", "responses": {"200": {"description": "Text"}}}},
                "/api/campaigns": {
                    "get": {"summary": "List campaigns", "responses": {"200": {"description": "List"}}},
                    "post": {
                        "summary": "Execute red-team campaign",
                        "security": [{"ApiKeyAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "target": {"type": "string", "enum": list(TARGETS)},
                                            "goals": {"type": "array", "items": {"type": "string"}},
                                        },
                                        "required": ["target"],
                                    }
                                }
                            },
                        },
                        "responses": {"201": {"description": "Campaign created"}, "400": {"description": "Bad Request"}},
                    },
                },
                "/api/campaigns/{id}/sarif": {
                    "get": {"summary": "Download SARIF v2.1.0 report", "responses": {"200": {"description": "SARIF"}}}
                },
                "/api/campaigns/{id}/export": {
                    "get": {"summary": "Export campaign CSV or JSON", "responses": {"200": {"description": "Export"}}}
                },
                "/api/owasp": {
                    "get": {"summary": "OWASP LLM 2025 catalog", "responses": {"200": {"description": "Catalog"}}}
                },
                "/api/guardrails/scan": {
                    "post": {
                        "summary": "Scan text with AgentShield guardrail",
                        "security": [{"ApiKeyAuth": []}],
                        "responses": {"200": {"description": "Scan analysis"}},
                    }
                },
            },
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
                }
            },
        }
        return jsonify(spec)

    @app.get("/docs")
    def api_docs():
        """Interactive, CSP-compliant API reference."""
        return render_template("docs.html")

    return app
