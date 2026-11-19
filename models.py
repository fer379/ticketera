from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

VALID_STATUSES = ("Abierto", "En Progreso", "Resuelto", "Cerrado")
VALID_PRIORITIES = ("Baja", "Media", "Alta", "Crítica")


def utcnow():
    return datetime.now(timezone.utc)


class Ticket(db.Model):
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(60), nullable=False, default="Soporte General")
    status = db.Column(db.String(20), nullable=False, default="Abierto", index=True)
    priority = db.Column(db.String(20), nullable=False, default="Media", index=True)
    created_by = db.Column(db.String(80), nullable=False, index=True)
    created_by_name = db.Column(db.String(120), nullable=False)
    assigned_to = db.Column(db.String(80), nullable=True, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    history = db.relationship(
        "TicketHistory",
        backref="ticket",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="TicketHistory.created_at.asc()",
    )


class TicketHistory(db.Model):
    __tablename__ = "ticket_history"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(
        db.Integer, db.ForeignKey("tickets.id"), nullable=False, index=True
    )
    author = db.Column(db.String(80), nullable=False)
    author_role = db.Column(db.String(30), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)