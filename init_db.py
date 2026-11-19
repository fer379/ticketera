from app import app
from models import Ticket, TicketHistory, db


def seed():
    with app.app_context():
        db.create_all()
        if Ticket.query.count() > 0:
            print("La base de datos ya contiene registros.")
            return

        t1 = Ticket(
            title="Sin acceso a carpeta compartida de Administración",
            description="El equipo de contaduría reporta error de permisos al mapear \\\\SRV-FS\\Admin.",
            category="Redes y Permisos",
            status="En Progreso",
            priority="Alta",
            created_by="usuario.test",
            created_by_name="Usuario Prueba",
            assigned_to="operador.test",
        )
        t2 = Ticket(
            title="Instalación de certificado VPN en notebook",
            description="Se requiere configurar cliente VPN para conexión remota.",
            category="Seguridad / VPN",
            status="Abierto",
            priority="Media",
            created_by="admin.test",
            created_by_name="Administrador Prueba",
            assigned_to="",
        )
        db.session.add_all([t1, t2])
        db.session.flush()

        db.session.add_all(
            [
                TicketHistory(
                    ticket_id=t1.id,
                    author="usuario.test",
                    author_role="Usuario",
                    action="Ticket creado",
                    comment="Solicitud inicial cargada.",
                ),
                TicketHistory(
                    ticket_id=t1.id,
                    author="operador.test",
                    author_role="Operador",
                    action="Estado: Abierto → En Progreso; Responsable: Sin asignar → operador.test",
                    comment="Revisando ACLs en el servidor de archivos.",
                ),
                TicketHistory(
                    ticket_id=t2.id,
                    author="admin.test",
                    author_role="Admin",
                    action="Ticket creado",
                    comment="Pendiente de asignación.",
                ),
            ]
        )
        db.session.commit()
        print("Base de datos inicializada con tickets de ejemplo.")


if __name__ == "__main__":
    seed()