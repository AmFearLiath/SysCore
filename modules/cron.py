import re
import shutil
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from modules.auth_users import login_required, role_required
from db import log_audit

cron_bp = Blueprint("cron", __name__, url_prefix="/cron")
MARKER = "# SYSCORE_MANAGED"

def get_crontab_lines():
    if not shutil.which("crontab"):
        return []
    res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if res.returncode != 0:
        return []
    return res.stdout.splitlines()

def save_crontab_lines(lines):
    if not shutil.which("crontab"):
        return True, ""
    content = "\n".join(lines).strip() + "\n"
    res = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True)
    return res.returncode == 0, res.stderr

@cron_bp.route("/")
@login_required
@role_required(["root_admin"])
def index():
    lines = get_crontab_lines()
    managed_jobs = []
    system_jobs = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or (stripped.startswith("#") and MARKER not in stripped):
            continue
        if stripped.endswith(MARKER):
            raw = stripped.replace(MARKER, "").strip()
            parts = raw.split(None, 5)
            if len(parts) == 6:
                managed_jobs.append({
                    "line_idx": idx,
                    "schedule": " ".join(parts[:5]),
                    "command": parts[5]
                })
        else:
            system_jobs.append(stripped)

    return render_template("cron.html", managed_jobs=managed_jobs, system_jobs=system_jobs)

@cron_bp.route("/add", methods=["POST"])
@login_required
@role_required(["root_admin"])
def add_job():
    schedule = request.form.get("schedule", "").strip()
    command = request.form.get("command", "").strip()

    if len(schedule.split()) != 5 or not re.match(r"^[0-9*,/-]+(\s+[0-9*,/-]+){4}$", schedule):
        flash("Ungültiges Cron-Zeitformat (erwartet werden 5 Felder, z.B. '0 * * * *').", "error")
        return redirect(url_for("cron.index"))

    if not command or "\n" in command or "\r" in command:
        flash("Ungültiger Befehl.", "error")
        return redirect(url_for("cron.index"))

    lines = get_crontab_lines()
    lines.append(f"{schedule} {command} {MARKER}")
    ok, err = save_crontab_lines(lines)
    if ok:
        log_audit(session.get("username"), "CRON_ADD", f"Cronjob hinzugefügt: {schedule} {command}", request.remote_addr)
        flash("Cronjob erfolgreich hinzugefügt.", "success")
    else:
        flash(f"Crontab Fehler: {err}", "error")
    return redirect(url_for("cron.index"))

@cron_bp.route("/delete/<int:line_idx>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def delete_job(line_idx):
    lines = get_crontab_lines()
    if 0 <= line_idx < len(lines) and lines[line_idx].strip().endswith(MARKER):
        deleted_line = lines.pop(line_idx)
        save_crontab_lines(lines)
        log_audit(session.get("username"), "CRON_DELETE", f"Cronjob gelöscht: {deleted_line}", request.remote_addr, "warning")
        flash("Cronjob entfernt.", "success")
    return redirect(url_for("cron.index"))
