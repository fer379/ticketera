"""Pruebas de formularios, permisos, fechas locales e informes CSV."""

import os
import unittest
from datetime import datetime, time, timezone
from types import SimpleNamespace
from unittest.mock import patch

with patch.dict(os.environ, {"SECRET_KEY": "test-secret"}):
    from app import app


class TicketFormTests(unittest.TestCase):
    """Valida las reglas visibles para los usuarios de la ticketera."""

    def setUp(self):
        self.original_access_start = app.config["ACCESS_START"]
        self.original_access_end = app.config["ACCESS_END"]
        app.config["ACCESS_START"] = time.min
        app.config["ACCESS_END"] = time.max

        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = {
                "username": "test.user",
                "display_name": "Test User",
                "role": "Usuario",
            }
            session["csrf_token"] = "test-csrf-token"

    def tearDown(self):
        app.config["ACCESS_START"] = self.original_access_start
        app.config["ACCESS_END"] = self.original_access_end

    def test_login_template_and_shared_static_assets_load(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("/static/css/style.css", body)
        self.assertIn("/static/js/script.js", body)

        css_response = self.client.get("/static/css/style.css")
        js_response = self.client.get("/static/js/script.js")
        try:
            self.assertEqual(css_response.status_code, 200)
            self.assertIn(
                "prefers-reduced-motion", css_response.get_data(as_text=True)
            )
            self.assertEqual(js_response.status_code, 200)
            self.assertIn("toggle-password", js_response.get_data(as_text=True))
        finally:
            css_response.close()
            js_response.close()

    def test_invalid_ticket_form_preserves_values_and_marks_fields(self):
        response = self.client.post(
            "/tickets/nuevo",
            data={
                "csrf_token": "test-csrf-token",
                "title": "abc",
                "category": "Hardware",
                "priority": "Alta",
                "description": "breve",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('value="abc"', body)
        self.assertIn('value="Hardware" selected', body)
        self.assertIn('value="Alta" selected', body)
        self.assertIn("breve</textarea>", body)
        self.assertIn("El título debe tener entre 4 y 150 caracteres.", body)
        self.assertIn("La descripción debe tener al menos 10 caracteres.", body)
        self.assertIn('id="description"', body)
        self.assertIn('name="description"', body)
        self.assertEqual(body.count('class="form-control is-invalid"'), 2)

    def test_datetime_filter_displays_argentina_time_for_utc_and_sqlite_values(self):
        format_datetime = app.jinja_env.filters["argentina_datetime"]
        aware_utc = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
        sqlite_naive_utc = datetime(2026, 1, 15, 12, 0)

        self.assertEqual(format_datetime(aware_utc), "15/01/2026 09:00")
        self.assertEqual(format_datetime(sqlite_naive_utc), "15/01/2026 09:00")

    def test_csv_export_uses_argentina_time_and_headers(self):
        ticket = SimpleNamespace(
            id=1,
            title="Test ticket",
            category="Hardware",
            status="Abierto",
            priority="Media",
            created_by="test.user",
            created_by_name="Test User",
            assigned_to="",
            created_at=datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 15, 13, 30, tzinfo=timezone.utc),
        )

        class FakeQuery:
            def order_by(self, *args):
                return self

            def all(self):
                return [ticket]

        with patch("app.visible_tickets_query", return_value=FakeQuery()):
            response = self.client.get("/reportes/exportar-csv")

        csv_content = response.data.decode("utf-8-sig")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Fecha_Creacion_Argentina_GMT-3", csv_content)
        self.assertIn("Ultima_Actualizacion_Argentina_GMT-3", csv_content)
        self.assertIn("15/01/2026 09:00:00", csv_content)
        self.assertIn("15/01/2026 10:30:00", csv_content)

    def test_user_can_comment_on_own_ticket_without_changing_ticket_fields(self):
        ticket = SimpleNamespace(
            id=1,
            created_by="test.user",
            status="Resuelto",
            priority="Alta",
            assigned_to="operator",
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        with patch("app.db.session.get", return_value=ticket):
            with patch("app.db.session.add") as add_history:
                with patch("app.db.session.commit") as commit:
                    response = self.client.post(
                        "/tickets/1",
                        data={
                            "csrf_token": "test-csrf-token",
                            "comment": "El problema continúa después de resolverlo.",
                            "status": "Cerrado",
                            "priority": "Baja",
                            "assigned_to": "another.operator",
                        },
                    )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(ticket.status, "Resuelto")
        self.assertEqual(ticket.priority, "Alta")
        self.assertEqual(ticket.assigned_to, "operator")
        self.assertGreater(ticket.updated_at, datetime(2026, 1, 1, tzinfo=timezone.utc))
        history_entry = add_history.call_args.args[0]
        self.assertEqual(history_entry.author, "test.user")
        self.assertEqual(history_entry.author_role, "Usuario")
        self.assertEqual(history_entry.action, "Observación del solicitante")
        self.assertEqual(
            history_entry.comment, "El problema continúa después de resolverlo."
        )
        commit.assert_called_once()

    def test_user_cannot_comment_on_another_users_ticket(self):
        ticket = SimpleNamespace(id=1, created_by="another.user")

        with patch("app.db.session.get", return_value=ticket):
            with patch("app.db.session.add") as add_history:
                response = self.client.post(
                    "/tickets/1",
                    data={
                        "csrf_token": "test-csrf-token",
                        "comment": "Este comentario no debe guardarse.",
                    },
                )

        self.assertEqual(response.status_code, 403)
        add_history.assert_not_called()

    def test_user_comment_is_required_and_length_is_validated(self):
        ticket = SimpleNamespace(
            id=1,
            created_by="test.user",
            created_by_name="Test User",
            title="Test ticket",
            description="Ticket description for testing.",
            category="Hardware",
            status="Resuelto",
            priority="Media",
            assigned_to="",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            history=[],
        )

        with patch("app.db.session.get", return_value=ticket):
            response = self.client.post(
                "/tickets/1",
                data={"csrf_token": "test-csrf-token", "comment": "   "},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Escribí una observación antes de enviarla.",
            response.get_data(as_text=True),
        )
        self.assertIn("Agregar una observación", response.get_data(as_text=True))

        long_comment = "x" * 2001
        with patch("app.db.session.get", return_value=ticket):
            with patch("app.db.session.add") as add_history:
                response = self.client.post(
                    "/tickets/1",
                    data={"csrf_token": "test-csrf-token", "comment": long_comment},
                )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("no puede superar los 2000 caracteres.", body)
        self.assertIn(long_comment, body)
        add_history.assert_not_called()

    def test_read_only_role_cannot_post_ticket_comments(self):
        ticket = SimpleNamespace(id=1, created_by="test.user")
        with self.client.session_transaction() as session:
            user = session["user"].copy()
            user["role"] = "Consulta"
            session["user"] = user

        with patch("app.db.session.get", return_value=ticket):
            response = self.client.post(
                "/tickets/1",
                data={
                    "csrf_token": "test-csrf-token",
                    "comment": "Quiero agregar un comentario",
                },
            )

        self.assertEqual(response.status_code, 403)

    def test_ticket_list_explains_each_role_view(self):
        role_titles = {
            "Admin": "Panel de administración",
            "Operador": "Bandeja de trabajo",
            "Usuario": "Mis solicitudes",
            "Consulta": "Consulta de tickets",
        }

        class FakeQuery:
            def all(self):
                return [
                    SimpleNamespace(
                        id=1,
                        title="Test ticket",
                        category="Hardware",
                        status="Abierto",
                        priority="Media",
                        created_by="test.user",
                        assigned_to="",
                        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    )
                ]

            def filter(self, *args):
                return self

            def order_by(self, *args):
                return self

        for role, title in role_titles.items():
            with self.subTest(role=role):
                with self.client.session_transaction() as session:
                    user = session["user"].copy()
                    user["role"] = role
                    session["user"] = user

                with patch("app.visible_tickets_query", return_value=FakeQuery()):
                    response = self.client.get("/")

                self.assertEqual(response.status_code, 200)
                body = response.get_data(as_text=True)
                self.assertIn(title, body)
                if role == "Usuario":
                    self.assertIn("Ver y comentar", body)


if __name__ == "__main__":
    unittest.main()
