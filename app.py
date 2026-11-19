import csv
import io
import secrets
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ad_auth import authenticate_ad
from config import Config
from models import Ticket, TicketHistory, VALID_PRIORITIES, VALID_STATUSES, db

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


# --- Helpers de horario y seguridad ---


def get_local_now() -> datetime:
    return datetime.now(ZoneInfo(app.config["TIMEZONE"]))


def is_within_access_hours() -> bool:
    now_t = get_local_now().time()
    start_t = app.config["ACCESS_START"]
    end_t = app.config["ACCESS_END"]
    if start_t <= end_t:
        return start_t <= now_t <= end_t
    return now_t >= start_t or now_t <= end_t


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(403, description="Token CSRF inválido o expirado.")


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def enforce_schedule_and_session():
    # Permite archivos estáticos y la pantalla de login
    if request.endpoint in ("static", "login", "schedule_blocked"):
        return

    if not is_within_access_hours():
        session.clear()
        return redirect(url_for("schedule_blocked"))

    if "user" not in session:
        return redirect(url_for("login"))


def roles_required(*allowed_roles):
    def decorator(view_fn):
        @wraps(view_fn)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user or user.get("role") not in allowed_roles:
                abort(403, description="No tenés permisos para realizar esta acción.")
            return view_fn(*args, **kwargs)

        return wrapped

    return decorator


def visible_tickets_query(user: dict):
    query = Ticket.query
    # Rol Usuario solo consulta sus propios tickets
    if user["role"] == "Usuario":
        query = query.filter(Ticket.created_by == user["username"])
    return query


# --- Rutas de autenticación ---


@app.route("/horario-restringido")
def schedule_blocked():
    now_str = get_local_now().strftime("%H:%M:%S")
    start_str = app.config["ACCESS_START"].strftime("%H:%M")
    end_str = app.config["ACCESS_END"].strftime("%H:%M")
    return (
        render_template(
            "login.html",
            blocked=True,
            now_str=now_str,
            start_str=start_str,
            end_str=end_str,
        ),
        403,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    now_str = get_local_now().strftime("%H:%M:%S")
    start_str = app.config["ACCESS_START"].strftime("%H:%M")
    end_str = app.config["ACCESS_END"].strftime("%H:%M")

    if not is_within_access_hours():
        session.clear()
        return (
            render_template(
                "login.html",
                blocked=True,
                now_str=now_str,
                start_str=start_str,
                end_str=end_str,
            ),
            403,
        )

    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user_info = authenticate_ad(username, password, app.config)
        if not user_info:
            flash(
                "Credenciales inválidas o usuario sin rol asignado en Active Directory.",
                "danger",
            )
            return render_template(
                "login.html",
                blocked=False,
                now_str=now_str,
                start_str=start_str,
                end_str=end_str,
            )

        session.clear()
        session["user"] = user_info
        get_csrf_token()
        flash(
            f"Bienvenido/a, {user_info['display_name']} (Rol: {user_info['role']}).",
            "success",
        )
        return redirect(url_for("tickets_list"))

    return render_template(
        "login.html",
        blocked=False,
        now_str=now_str,
        start_str=start_str,
        end_str=end_str,
    )


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


# --- Rutas de Tickets y Reportes ---


@app.route("/")
def tickets_list():
    user = session["user"]
    status_filter = request.args.get("status", "").strip()
    priority_filter = request.args.get("priority", "").strip()
    search_q = request.args.get("q", "").strip()[:100]

    base_q = visible_tickets_query(user)

    # Métricas para reportes rápidos
    all_visible = base_q.all()
    stats = {
        "total": len(all_visible),
        "Abierto": sum(1 for t in all_visible if t.status == "Abierto"),
        "En Progreso": sum(1 for t in all_visible if t.status == "En Progreso"),
        "Resuelto": sum(1 for t in all_visible if t.status == "Resuelto"),
        "Cerrado": sum(1 for t in all_visible if t.status == "Cerrado"),
    }

    # Filtros parametrizados (ORM previene SQLi)
    filtered_q = base_q
    if status_filter in VALID_STATUSES:
        filtered_q = filtered_q.filter(Ticket.status == status_filter)
    if priority_filter in VALID_PRIORITIES:
        filtered_q = filtered_q.filter(Ticket.priority == priority_filter)
    if search_q:
        like_pattern = f"%{search_q}%"
        filtered_q = filtered_q.filter(
            db.or_(
                Ticket.title.ilike(like_pattern),
                Ticket.description.ilike(like_pattern),
                Ticket.assigned_to.ilike(like_pattern),
            )
        )

    tickets = filtered_q.order_by(Ticket.updated_at.desc()).all()

    return render_template(
        "tickets_list.html",
        user=user,
        tickets=tickets,
        stats=stats,
        statuses=VALID_STATUSES,
        priorities=VALID_PRIORITIES,
        status_filter=status_filter,
        priority_filter=priority_filter,
        search_q=search_q,
    )


@app.route("/tickets/nuevo", methods=["GET", "POST"])
@roles_required("Admin", "Operador", "Usuario")
def ticket_new():
    user = session["user"]
    if request.method == "POST":
        validate_csrf()
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "Soporte General").strip()[:60]
        priority = request.form.get("priority", "Media").strip()
        description = request.form.get("description", "").strip()

        if len(title) < 4 or len(title) > 150:
            flash("El título debe tener entre 4 y 150 caracteres.", "danger")
            return render_template(
                "ticket_new.html", user=user, priorities=VALID_PRIORITIES
            )

        if len(description) < 10:
            flash("La descripción debe tener al menos 10 caracteres.", "danger")
            return render_template(
                "ticket_new.html", user=user, priorities=VALID_PRIORITIES
            )

        if priority not in VALID_PRIORITIES:
            priority = "Media"

        ticket = Ticket(
            title=title,
            category=category or "Soporte General",
            priority=priority,
            status="Abierto",
            description=description,
            created_by=user["username"],
            created_by_name=user["display_name"],
        )
        db.session.add(ticket)
        db.session.flush()

        history_entry = TicketHistory(
            ticket_id=ticket.id,
            author=user["username"],
            author_role=user["role"],
            action="Ticket creado",
            comment="Solicitud registrada en el sistema.",
        )
        db.session.add(history_entry)
        db.session.commit()

        flash(f"Ticket #{ticket.id} creado correctamente.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    return render_template("ticket_new.html", user=user, priorities=VALID_PRIORITIES)


@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
def ticket_detail(ticket_id: int):
    user = session["user"]
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)

    if user["role"] == "Usuario" and ticket.created_by != user["username"]:
        abort(403, description="Solo podés consultar tus propios tickets.")

    if request.method == "POST":
        validate_csrf()
        if user["role"] == "Consulta":
            abort(403, description="El rol Consulta tiene acceso de solo lectura.")

        comment_text = request.form.get("comment", "").strip()
        changes = []

        # Admin y Operador pueden gestionar estado, prioridad y responsable
        if user["role"] in ("Admin", "Operador"):
            new_status = request.form.get("status", ticket.status).strip()
            new_priority = request.form.get("priority", ticket.priority).strip()
            new_assigned = request.form.get("assigned_to", "").strip()[:80]

            if new_status in VALID_STATUSES and new_status != ticket.status:
                changes.append(f"Estado: {ticket.status} → {new_status}")
                ticket.status = new_status

            if new_priority in VALID_PRIORITIES and new_priority != ticket.priority:
                changes.append(f"Prioridad: {ticket.priority} → {new_priority}")
                ticket.priority = new_priority

            if new_assigned != (ticket.assigned_to or ""):
                prev = ticket.assigned_to or "Sin asignar"
                curr = new_assigned or "Sin asignar"
                changes.append(f"Responsable: {prev} → {curr}")
                ticket.assigned_to = new_assigned

        if not changes and not comment_text:
            flash("No se detectaron cambios ni comentarios para registrar.", "warning")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))

        action_summary = "; ".join(changes) if changes else "Comentario de seguimiento"
        entry = TicketHistory(
            ticket_id=ticket.id,
            author=user["username"],
            author_role=user["role"],
            action=action_summary,
            comment=comment_text or None,
        )
        db.session.add(entry)
        db.session.commit()

        flash("Ticket actualizado correctamente.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    return render_template(
        "ticket_detail.html",
        user=user,
        ticket=ticket,
        statuses=VALID_STATUSES,
        priorities=VALID_PRIORITIES,
    )


@app.route("/tickets/<int:ticket_id>/eliminar", methods=["POST"])
@roles_required("Admin")
def ticket_delete(ticket_id: int):
    validate_csrf()
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)
    db.session.delete(ticket)
    db.session.commit()
    flash(f"Ticket #{ticket_id} eliminado por Administrador.", "info")
    return redirect(url_for("tickets_list"))


@app.route("/reportes/exportar-csv")
def export_csv():
    user = session["user"]
    status_filter = request.args.get("status", "").strip()
    priority_filter = request.args.get("priority", "").strip()

    query = visible_tickets_query(user)
    if status_filter in VALID_STATUSES:
        query = query.filter(Ticket.status == status_filter)
    if priority_filter in VALID_PRIORITIES:
        query = query.filter(Ticket.priority == priority_filter)

    tickets = query.order_by(Ticket.id.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(
        [
            "ID",
            "Titulo",
            "Categoria",
            "Estado",
            "Prioridad",
            "Solicitante_AD",
            "Nombre_Solicitante",
            "Responsable_Asignado",
            "Fecha_Creacion_UTC",
            "Ultima_Actualizacion_UTC",
        ]
    )

    for t in tickets:
        writer.writerow(
            [
                t.id,
                t.title,
                t.category,
                t.status,
                t.priority,
                t.created_by,
                t.created_by_name,
                t.assigned_to or "Sin asignar",
                t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                t.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            ]
        )

    # BOM UTF-8 para abrir directo en Microsoft Excel sin problemas de acentos
    csv_bytes = ("\ufeff" + output.getvalue()).encode("utf-8")
    response = make_response(csv_bytes)
    filename = f"reporte_tickets_{get_local_now().strftime('%Y%m%d_%H%M')}.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=False)