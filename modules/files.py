import os
import re
import shutil
import zipfile
import stat
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.utils import secure_filename
from config import WEB_ROOT_BASE
from modules.auth_users import login_required, role_required
from modules.system_agent import run_privileged
from db import log_audit

files_bp = Blueprint("files", __name__, url_prefix="/files")

EDITABLE_EXTENSIONS = {
    ".php", ".html", ".htm", ".css", ".js", ".json", ".txt", ".md",
    ".xml", ".env", ".htaccess", ".ini", ".yml", ".yaml", ".sql", ".sh"
}

def get_available_domains():
    """Ermittelt alle verfügbaren Domain-Verzeichnisse unter /var/www (SEC-003)"""
    domains = []
    base = os.path.realpath(WEB_ROOT_BASE)
    if os.path.exists(base):
        for item in sorted(os.listdir(base)):
            p = os.path.join(base, item)
            if os.path.isdir(p) and not item.startswith("."):
                domains.append(item)
    return domains

def resolve_safe_domain_path(domain, rel_path=""):
    """
    Strikte Domain-Isolation für den Dateimanager (SEC-003):
    - Erzwingt Verbleib im spezifischen Domain-Root /var/www/<domain>/
    - Kein Zugriff auf /var/www, fremde Domains, /etc, /opt/syscore
    - Kanonische commonpath-Prüfung gegen Path Traversal
    - Rejection von '..' Traversal und absoluten Pfaden
    - Symlink-Schutz: Symlinks dürfen nicht aus dem Domain-Root ausbrechen
    """
    clean_domain = (domain or "").strip().lower()
    if not clean_domain or not re.match(r"^[a-z0-9.-]{1,128}$", clean_domain):
        raise ValueError("Ungültige Domain für Dateimanager.")

    web_base = os.path.realpath(WEB_ROOT_BASE)
    domain_base = os.path.realpath(os.path.join(web_base, clean_domain))

    # Sicherstellen, dass das Domain-Verzeichnis selbst innerhalb von WEB_ROOT_BASE liegt
    if os.path.commonpath([web_base, domain_base]) != web_base:
        raise ValueError(f"Sicherheitsrisiko: Ungültige Domain-Wurzel: {clean_domain}")

    os.makedirs(domain_base, exist_ok=True)

    clean_rel = (rel_path or "").strip().replace("\\", "/").lstrip("/")
    parts = [p for p in clean_rel.split("/") if p]
    if ".." in parts:
        raise ValueError(f"Sicherheitsrisiko: Pfad-Traversal '..' abgewiesen: {rel_path}")

    target = os.path.realpath(os.path.join(domain_base, clean_rel))

    # Strikte kanonische Domain-Grenzenprüfung (SEC-003)
    if os.path.commonpath([domain_base, target]) != domain_base:
        raise ValueError(f"Sicherheitsrisiko: Zugriff außerhalb der Domain '{clean_domain}' verweigert: {rel_path}")

    # Symlink-Schutz: Prüfen, ob Symlinks aus der Domain ausbrechen
    if os.path.islink(target):
        link_target = os.path.realpath(target)
        if os.path.commonpath([domain_base, link_target]) != domain_base:
            raise ValueError(f"Sicherheitsrisiko: Symlink zeigt auf ein Ziel außerhalb der Domain: {rel_path}")

    actual_rel = os.path.relpath(target, domain_base).replace("\\", "/")
    safe_rel = "" if actual_rel == "." else actual_rel
    return domain_base, target, safe_rel

def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} TB"

def get_permissions_octal(path):
    try:
        mode = os.stat(path).st_mode
        return oct(mode)[-3:]
    except Exception:
        return "755"

@files_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    available_domains = get_available_domains()
    current_domain = request.args.get("domain") or session.get("active_file_domain")

    if not current_domain or current_domain not in available_domains:
        current_domain = available_domains[0] if available_domains else "default"

    session["active_file_domain"] = current_domain
    rel_path = request.args.get("path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(current_domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=current_domain))

    if not os.path.exists(abs_path):
        flash("Pfad existiert nicht.", "error")
        return redirect(url_for("files.index", domain=current_domain))

    breadcrumbs = []
    if safe_rel:
        parts = safe_rel.split("/")
        for i, part in enumerate(parts):
            breadcrumbs.append({"name": part, "path": "/".join(parts[:i+1])})

    entries = []
    try:
        dir_items = os.listdir(abs_path)
    except OSError:
        dir_items = []

    for name in sorted(dir_items, key=lambda x: (not os.path.isdir(os.path.join(abs_path, x)), x.lower())):
        full = os.path.join(abs_path, name)
        is_dir = os.path.isdir(full)
        is_link = os.path.islink(full)
        ext = os.path.splitext(name)[1].lower()
        size_str = "-"
        if not is_dir:
            try:
                size_str = format_size(os.path.getsize(full))
            except OSError:
                size_str = "0 B"

        entries.append({
            "name": name,
            "rel_path": os.path.join(safe_rel, name).replace("\\", "/").lstrip("/"),
            "is_dir": is_dir,
            "is_link": is_link,
            "size": size_str,
            "permissions": get_permissions_octal(full),
            "editable": not is_dir and (ext in EDITABLE_EXTENSIONS or name.startswith(".")),
            "is_zip": not is_dir and ext == ".zip"
        })

    return render_template(
        "files.html",
        current_domain=current_domain,
        available_domains=available_domains,
        current_path=safe_rel,
        breadcrumbs=breadcrumbs,
        entries=entries,
        edit_file=None
    )

@files_bp.route("/edit", methods=["GET", "POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def edit():
    domain = request.values.get("domain") or session.get("active_file_domain", "")
    rel_path = request.values.get("path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_rel = os.path.dirname(safe_rel)

    if not os.path.isfile(abs_path):
        flash("Datei nicht gefunden.", "error")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    if request.method == "POST":
        content = request.form.get("content", "").replace("\r\n", "\n")
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        if shutil.which("chown"):
            run_privileged(["chown", "www-data:www-data", abs_path])
        log_audit(session.get("username"), "FILE_EDIT", f"Datei '{domain}/{safe_rel}' bearbeitet", request.remote_addr)
        flash(f"Datei '{os.path.basename(abs_path)}' gespeichert.", "success")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        flash("Binärdatei kann nicht im Texteditor geöffnet werden.", "error")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    ext = os.path.splitext(abs_path)[1].lower()
    return render_template(
        "files.html",
        current_domain=domain,
        available_domains=get_available_domains(),
        current_path=parent_rel,
        breadcrumbs=[],
        entries=[],
        edit_file={"name": os.path.basename(abs_path), "path": safe_rel, "content": content, "ext": ext}
    )

@files_bp.route("/mkdir", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def mkdir():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("current_path", "")
    folder_name = secure_filename(request.form.get("folder_name", "").strip())

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    if folder_name and "/" not in folder_name and ".." not in folder_name:
        new_dir = os.path.join(abs_path, folder_name)
        os.makedirs(new_dir, exist_ok=True)
        if shutil.which("chown"):
            run_privileged(["chown", "-R", "www-data:www-data", new_dir])
        flash(f"Ordner '{folder_name}' erstellt.", "success")
    return redirect(url_for("files.index", domain=domain, path=safe_rel))

@files_bp.route("/mkfile", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def mkfile():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("current_path", "")
    file_name = request.form.get("file_name", "").strip()

    if file_name and "/" not in file_name and "\\" not in file_name and ".." not in file_name:
        try:
            domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
            new_file = os.path.join(abs_path, file_name)
            if not os.path.exists(new_file):
                with open(new_file, "w", encoding="utf-8") as f:
                    f.write("")
                if shutil.which("chown"):
                    run_privileged(["chown", "www-data:www-data", new_file])
                flash(f"Datei '{file_name}' erstellt.", "success")
            return redirect(url_for("files.index", domain=domain, path=safe_rel))
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("files.index", domain=domain))

    flash("Ungültiger Dateiname.", "error")
    return redirect(url_for("files.index", domain=domain, path=rel_path))

@files_bp.route("/rename", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def rename():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("path", "")
    new_name = request.form.get("new_name", "").strip()

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_dir = os.path.dirname(abs_path)
    parent_rel = os.path.dirname(safe_rel)

    if not new_name or "/" in new_name or "\\" in new_name or ".." in new_name:
        flash("Ungültiger neuer Dateiname.", "error")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    dest_path = os.path.join(parent_dir, new_name)
    if os.path.exists(dest_path):
        flash("Ein Element mit diesem Namen existiert bereits.", "error")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    try:
        os.rename(abs_path, dest_path)
        log_audit(session.get("username"), "FILE_RENAME", f"'{domain}/{safe_rel}' -> '{new_name}' umbenannt", request.remote_addr)
        flash(f"Erfolgreich umbenannt in '{new_name}'.", "success")
    except Exception as e:
        flash(f"Fehler beim Umbenennen: {e}", "error")

    return redirect(url_for("files.index", domain=domain, path=parent_rel))

@files_bp.route("/chmod", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def chmod_entry():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("path", "")
    permissions = request.form.get("permissions", "755").strip()

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_rel = os.path.dirname(safe_rel)

    if re.match(r"^[0-7]{3,4}$", permissions):
        try:
            mode = int(permissions, 8)
            os.chmod(abs_path, mode)
            log_audit(session.get("username"), "FILE_CHMOD", f"Rechte für '{domain}/{safe_rel}' auf {permissions} geändert", request.remote_addr)
            flash(f"Berechtigungen für '{os.path.basename(abs_path)}' auf {permissions} geändert.", "success")
        except Exception as e:
            flash(f"Fehler: {e}", "error")
    else:
        flash("Ungültiges Berechtigungs-Format (z.B. 755 oder 644).", "error")

    return redirect(url_for("files.index", domain=domain, path=parent_rel))

@files_bp.route("/zip", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def zip_folder():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_rel = os.path.dirname(safe_rel)
    base_name = os.path.basename(abs_path)
    zip_name = f"{base_name}.zip"
    zip_dest = os.path.join(os.path.dirname(abs_path), zip_name)

    try:
        with zipfile.ZipFile(zip_dest, "w", zipfile.ZIP_DEFLATED) as z:
            if os.path.isdir(abs_path):
                for root, _, files in os.walk(abs_path):
                    for file in files:
                        full_f = os.path.join(root, file)
                        # Symlinks prüfen: dürfen nicht aus der Domain zeigen
                        if os.path.islink(full_f):
                            resolved = os.path.realpath(full_f)
                            if os.path.commonpath([domain_base, resolved]) != domain_base:
                                continue
                        arc_f = os.path.relpath(full_f, os.path.dirname(abs_path))
                        z.write(full_f, arc_f)
            else:
                z.write(abs_path, base_name)
        flash(f"Archiv '{zip_name}' erstellt.", "success")
    except Exception as e:
        flash(f"Komprimierung fehlgeschlagen: {e}", "error")

    return redirect(url_for("files.index", domain=domain, path=parent_rel))

@files_bp.route("/unzip", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def unzip_file():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_rel = os.path.dirname(safe_rel)
    extract_dir = os.path.dirname(abs_path)

    if not abs_path.endswith(".zip"):
        flash("Keine .zip Datei.", "error")
        return redirect(url_for("files.index", domain=domain, path=parent_rel))

    try:
        with zipfile.ZipFile(abs_path, "r") as z:
            for member in z.infolist():
                fname = member.filename.replace("\\", "/")
                if fname.startswith("/") or ".." in fname.split("/"):
                    raise ValueError(f"Sicherheitsrisiko (Zip-Slip): Traversal im Archiv: {member.filename}")
                member_path = os.path.realpath(os.path.join(extract_dir, fname))
                if os.path.commonpath([domain_base, member_path]) != domain_base:
                    raise ValueError(f"Sicherheitsrisiko: Entpacken bricht aus Domain '{domain}' aus: {member.filename}")
            z.extractall(extract_dir)

        if shutil.which("chown"):
            run_privileged(["chown", "-R", "www-data:www-data", extract_dir])
        flash(f"Archiv '{os.path.basename(abs_path)}' erfolgreich entpackt.", "success")
    except Exception as e:
        flash(f"Entpacken fehlgeschlagen: {e}", "error")

    return redirect(url_for("files.index", domain=domain, path=parent_rel))

@files_bp.route("/upload", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def upload():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("current_path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    files = request.files.getlist("files")
    count = 0
    for f in files:
        if f and f.filename:
            fname = secure_filename(f.filename)
            dest = os.path.join(abs_path, fname)
            f.save(dest)
            if shutil.which("chown"):
                run_privileged(["chown", "www-data:www-data", dest])
            count += 1
    if count:
        flash(f"{count} Datei(en) erfolgreich hochgeladen.", "success")
    return redirect(url_for("files.index", domain=domain, path=safe_rel))

@files_bp.route("/download")
@login_required
@role_required(["root_admin", "web_admin"])
def download():
    domain = request.args.get("domain") or session.get("active_file_domain", "")
    rel_path = request.args.get("path", "")

    try:
        domain_base, abs_path, _ = resolve_safe_domain_path(domain, rel_path)
        if os.path.isfile(abs_path):
            return send_file(abs_path, as_attachment=True)
    except Exception:
        pass
    return redirect(url_for("files.index", domain=domain))

@files_bp.route("/delete", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete():
    domain = request.form.get("domain") or session.get("active_file_domain", "")
    rel_path = request.form.get("path", "")

    try:
        domain_base, abs_path, safe_rel = resolve_safe_domain_path(domain, rel_path)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("files.index", domain=domain))

    parent_rel = os.path.dirname(safe_rel)

    # Verhindern, dass der Domain-Wurzelordner selbst gelöscht wird
    if abs_path == domain_base:
        flash(f"Das Basisverzeichnis der Domain '{domain}' kann nicht gelöscht werden.", "error")
        return redirect(url_for("files.index", domain=domain))

    try:
        if os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        log_audit(session.get("username"), "FILE_DELETE", f"'{domain}/{safe_rel}' gelöscht", request.remote_addr, "warning")
        flash(f"'{os.path.basename(abs_path)}' gelöscht.", "success")
    except Exception as e:
        flash(f"Fehler beim Löschen: {e}", "error")

    return redirect(url_for("files.index", domain=domain, path=parent_rel))
