"""Rutas web, permisos, validaciones y exportación de la ticketera."""

import csv
import io
import secrets
from datetime import datetime, timezone
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

from ad_auth import (
    ADUserNotFoundError,
    ADRoleNotAssignedError,
    authenticate_ad,
)
from config import Config
from models import Ticket, TicketHistory, VALID_PRIORITIES, VALID_STATUSES, db

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

MAX_COMMENT_LENGTH = 2000


# --- Helpers de horario y seguridad ---


def get_local_now() -> datetime:
    """Devuelve la hora actual en la zona horaria configurada."""
    return datetime.now(ZoneInfo(app.config["TIMEZONE"]))


def to_local_datetime(value: datetime) -> datetime:
    """Interpreta fechas ingenuas de SQLite como UTC y las convierte a hora local."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(app.config["TIMEZONE"]))


def format_argentina_datetime(value: datetime) -> str:
    """Formatea una fecha para mostrarla en las pantallas de la aplicación."""
    return to_local_datetime(value).strftime("%d/%m/%Y %H:%M")


app.jinja_env.filters["argentina_datetime"] = format_argentina_datetime


def is_within_access_hours() -> bool:
    """Indica si la hora local actual está dentro del horario permitido."""
    now_t = get_local_now().time()
    start_t = app.config["ACCESS_START"]
    end_t = app.config["ACCESS_END"]
    if start_t <= end_t:
        return start_t <= now_t <= end_t
    return now_t >= start_t or now_t <= end_t


def get_csrf_token() -> str:
    """Crea y conserva el token que protege los formularios contra CSRF."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    """Rechaza operaciones POST que no tengan el token de sesión correcto."""
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(403, description="Token CSRF inválido o expirado.")


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def enforce_schedule_and_session():
    """Exige horario habilitado y una sesión iniciada para las rutas privadas."""
    # Permite archivos estáticos y la pantalla de login
    if request.endpoint in ("static", "login", "schedule_blocked"):
        return

    if not is_within_access_hours():
        session.clear()
        return redirect(url_for("schedule_blocked"))

    if "user" not in session:
        return redirect(url_for("login"))


def roles_required(*allowed_roles):
    """Limita una ruta a los roles indicados."""
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
    """Devuelve todos los tickets visibles para el rol autenticado."""
    query = Ticket.query
    # Rol Usuario solo consulta sus propios tickets
    if user["role"] == "Usuario":
        query = query.filter(Ticket.created_by == user["username"])
    return query


# --- Rutas de autenticación ---


@app.route("/horario-restringido")
def schedule_blocked():
    """Muestra la pantalla informativa cuando el acceso está fuera de horario."""
    now_str = get_local_now().strftime("%H:%M:%S")
    start_str = app.config["ACCESS_START"].strftime("%H:%M")
    end_str = app.config["ACCESS_END"].strftime("%H:%M")
    return (
        render_template(
            "auth/login.html",
            blocked=True,
            domain=app.config["AD_DOMAIN"],
            now_str=now_str,
            start_str=start_str,
            end_str=end_str,
        ),
        403,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Autentica con AD y crea la sesión de la aplicación."""
    now_str = get_local_now().strftime("%H:%M:%S")
    start_str = app.config["ACCESS_START"].strftime("%H:%M")
    end_str = app.config["ACCESS_END"].strftime("%H:%M")

    if not is_within_access_hours():
        session.clear()
        return (
            render_template(
                "auth/login.html",
                blocked=True,
                domain=app.config["AD_DOMAIN"],
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

        try:
            user_info = authenticate_ad(username, password, app.config)
        except ADUserNotFoundError:
            flash(
                "Active Directory aceptó la autenticación, pero no encontró "
                "la cuenta dentro de AD_BASE_DN. Verificá el usuario y el DN base.",
                "danger",
            )
            return render_template(
                "auth/login.html",
                blocked=False,
                domain=app.config["AD_DOMAIN"],
                now_str=now_str,
                start_str=start_str,
                end_str=end_str,
            )
        except ADRoleNotAssignedError:
            flash(
                "Active Directory aceptó la autenticación, pero la cuenta no "
                "tiene un rol de Ticketera reconocido. Verificá su grupo/OU y "
                "el DN exacto en ROLE_DN_MAP de config.py.",
                "danger",
            )
            return render_template(
                "auth/login.html",
                blocked=False,
                domain=app.config["AD_DOMAIN"],
                now_str=now_str,
                start_str=start_str,
                end_str=end_str,
            )

        if not user_info:
            flash(
                "No se pudo validar el usuario o la contraseña. Ingresá tu "
                "nombre de usuario sin @ y verificá la contraseña.",
                "danger",
            )
            return render_template(
                "auth/login.html",
                blocked=False,
                domain=app.config["AD_DOMAIN"],
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
        "auth/login.html",
        blocked=False,
        domain=app.config["AD_DOMAIN"],
        now_str=now_str,
        start_str=start_str,
        end_str=end_str,
    )


@app.route("/logout", methods=["POST"])
def logout():
    """Cierra la sesión actual después de validar el formulario."""
    validate_csrf()
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


# --- Rutas de Tickets y Reportes ---


@app.route("/")
def tickets_list():
    """Lista tickets, métricas y filtros respetando la visibilidad por rol."""
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
        "tickets/list.html",
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
    """Valida y registra un ticket nuevo o devuelve el formulario con errores."""
    user = session["user"]
    if request.method == "POST":
        validate_csrf()
        form_data = {
            "title": request.form.get("title", "").strip(),
            "category": (
                request.form.get("category", "Soporte General").strip()[:60]
                or "Soporte General"
            ),
            "priority": request.form.get("priority", "Media").strip(),
            "description": request.form.get("description", "").strip(),
        }
        if form_data["priority"] not in VALID_PRIORITIES:
            form_data["priority"] = "Media"

        errors = {}
        title = form_data["title"]
        category = form_data["category"]
        priority = form_data["priority"]
        description = form_data["description"]

        if not title:
            errors["title"] = "Ingresá un título para el ticket."
        elif len(title) < 4 or len(title) > 150:
            errors["title"] = "El título debe tener entre 4 y 150 caracteres."

        if not description:
            errors["description"] = "Ingresá una descripción del problema."
        elif len(description) < 10:
            errors["description"] = (
                "La descripción debe tener al menos 10 caracteres."
            )

        if errors:
            return render_template(
                "tickets/new.html",
                user=user,
                priorities=VALID_PRIORITIES,
                form_data=form_data,
                errors=errors,
            )

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

    return render_template(
        "tickets/new.html",
        user=user,
        priorities=VALID_PRIORITIES,
        form_data={
            "title": "",
            "category": "Soporte General",
            "priority": "Media",
            "description": "",
        },
        errors={},
    )


@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
def ticket_detail(ticket_id: int):
    """Muestra el detalle y procesa comentarios o actualizaciones autorizadas."""
    user = session["user"]
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)

    if user["role"] == "Usuario" and ticket.created_by != user["username"]:
        abort(403, description="Solo podés consultar tus propios tickets.")

    if request.method == "POST":
        validate_csrf()
        is_staff = user["role"] in ("Admin", "Operador")
        if not is_staff and user["role"] != "Usuario":
            abort(
                403,
                description="Tu rol tiene acceso de solo lectura a los tickets.",
            )

        comment_text = request.form.get("comment", "").strip()
        errors = {}
        if user["role"] == "Usuario" and not comment_text:
            errors["comment"] = "Escribí una observación antes de enviarla."
        elif len(comment_text) > MAX_COMMENT_LENGTH:
            errors["comment"] = (
                f"El comentario no puede superar los {MAX_COMMENT_LENGTH} caracteres."
            )

        if errors:
            return render_template(
                "tickets/detail.html",
                user=user,
                ticket=ticket,
                statuses=VALID_STATUSES,
                priorities=VALID_PRIORITIES,
                comment_text=comment_text,
                errors=errors,
            )

        changes = []

        # Admin y Operador pueden gestionar estado, prioridad y responsable
        if is_staff:
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

        if changes:
            action_summary = "; ".join(changes)
        elif user["role"] == "Usuario":
            action_summary = "Observación del solicitante"
        else:
            action_summary = "Comentario de seguimiento"

        entry = TicketHistory(
            ticket_id=ticket.id,
            author=user["username"],
            author_role=user["role"],
            action=action_summary,
            comment=comment_text or None,
        )
        db.session.add(entry)
        ticket.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        if user["role"] == "Usuario":
            flash("Tu observación se agregó al historial del ticket.", "success")
        else:
            flash("Ticket actualizado correctamente.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    return render_template(
        "tickets/detail.html",
        user=user,
        ticket=ticket,
        statuses=VALID_STATUSES,
        priorities=VALID_PRIORITIES,
        comment_text="",
        errors={},
    )


@app.route("/tickets/<int:ticket_id>/eliminar", methods=["POST"])
@roles_required("Admin")
def ticket_delete(ticket_id: int):
    """Elimina un ticket; esta operación es exclusiva del rol Admin."""
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
    """Exporta en CSV los tickets visibles y filtrados en hora argentina."""
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
            "Fecha_Creacion_Argentina_GMT-3",
            "Ultima_Actualizacion_Argentina_GMT-3",
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
                to_local_datetime(t.created_at).strftime("%d/%m/%Y %H:%M:%S"),
                to_local_datetime(t.updated_at).strftime("%d/%m/%Y %H:%M:%S"),
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