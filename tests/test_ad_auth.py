"""Pruebas de autenticación AD, formatos de usuario y asignación de roles."""

import unittest
import os
from types import SimpleNamespace
from unittest.mock import patch

from ldap3 import NTLM, SIMPLE
from ldap3.core.exceptions import LDAPSocketOpenError

from ad_auth import (
    ADConnectionError,
    ADRoleNotAssignedError,
    _resolve_role,
    authenticate_ad,
    get_password_last_set,
)

with patch.dict(os.environ, {"SECRET_KEY": "test-secret"}):
    from config import Config


ROLE_DN_MAP = {
    "cn=ticketera_admin,ou=ticketera_admin,ou=ticketera,dc=ifts,dc=local": "Admin",
    "cn=ticketera_usuario,ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
    "ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
}


class AdAuthTests(unittest.TestCase):
    """Comprueba cómo el módulo LDAP interpreta respuestas del directorio."""

    def test_resolves_nested_group_membership(self):
        attributes = {
            "memberOf": [
                "CN=ticketera_admin,OU=ticketera_admin,OU=ticketera,DC=ifts,DC=local"
            ]
        }

        self.assertEqual(_resolve_role(attributes, ROLE_DN_MAP), "Admin")

    def test_resolves_screenshot_admin_group_mapping(self):
        attributes = {
            "memberOf": [
                "CN=GG_Admin,OU=ticketera_admin,OU=ticketera,DC=ifts,DC=local"
            ]
        }

        self.assertEqual(_resolve_role(attributes, Config.ROLE_DN_MAP), "Admin")

    def test_resolves_consultores_security_group_from_ad(self):
        attributes = {
            "memberOf": [
                "CN=GG_Consultores,OU=ticketera,DC=ifts,DC=local"
            ]
        }

        self.assertEqual(_resolve_role(attributes, Config.ROLE_DN_MAP), "Consulta")

    def test_resolves_user_in_role_ou(self):
        attributes = {
            "distinguishedName": [
                "CN=Alice,OU=Soporte,OU=ticketera_usuario,OU=ticketera,DC=ifts,DC=local"
            ]
        }

        self.assertEqual(_resolve_role(attributes, ROLE_DN_MAP), "Usuario")

    def test_rejects_conflicting_group_roles(self):
        attributes = {
            "memberOf": [
                "CN=ticketera_admin,OU=ticketera_admin,OU=ticketera,DC=ifts,DC=local",
                "CN=ticketera_usuario,OU=ticketera_usuario,OU=ticketera,DC=ifts,DC=local",
            ]
        }

        self.assertIsNone(_resolve_role(attributes, ROLE_DN_MAP))

    def test_authenticates_and_returns_app_user_shape(self):
        entry = SimpleNamespace(
            entry_attributes_as_dict={
                "sAMAccountName": "alice",
                "displayName": "Alice Example",
                "memberOf": [
                    "CN=ticketera_admin,OU=ticketera_admin,OU=ticketera,DC=ifts,DC=local"
                ],
            }
        )

        class FakeConnection:
            result = {"result": 0}
            entries = [entry]
            bound = False
            last_instance = None

            def __init__(self, server, **kwargs):
                self.kwargs = kwargs
                type(self).last_instance = self

            def bind(self):
                self.bound = True
                return True

            def search(self, **kwargs):
                self.search_kwargs = kwargs
                return True

            def unbind(self):
                self.bound = False
                return True

        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "ROLE_DN_MAP": ROLE_DN_MAP,
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection", FakeConnection):
            user = authenticate_ad("alice", "not-a-real-password", config)
            self.assertEqual(
                FakeConnection.last_instance.kwargs["authentication"], SIMPLE
            )
            self.assertEqual(
                FakeConnection.last_instance.kwargs["user"],
                "alice@IFTS.local",
            )
            upn_user = authenticate_ad(
                "alice@IFTS.local", "not-a-real-password", config
            )
            self.assertEqual(
                FakeConnection.last_instance.kwargs["authentication"], SIMPLE
            )
            self.assertEqual(
                FakeConnection.last_instance.kwargs["user"], "alice@IFTS.local"
            )
            self.assertEqual(
                FakeConnection.last_instance.search_kwargs["search_filter"],
                "(|(sAMAccountName=alice)(userPrincipalName=alice@IFTS.local))",
            )
            netbios_user = authenticate_ad(
                r"IFTS\alice", "not-a-real-password", config
            )
            self.assertEqual(
                FakeConnection.last_instance.kwargs["authentication"], NTLM
            )
            self.assertEqual(
                FakeConnection.last_instance.kwargs["user"], r"IFTS\alice"
            )

        self.assertEqual(
            user,
            {
                "username": "alice",
                "display_name": "Alice Example",
                "role": "Admin",
            },
        )
        self.assertEqual(
            FakeConnection.last_instance.kwargs["authentication"], NTLM
        )
        self.assertEqual(netbios_user["username"], "alice")
        self.assertEqual(upn_user["username"], "alice")

    def test_reads_pwd_last_set_with_the_configured_reader_account(self):
        entry = SimpleNamespace(
            entry_attributes_as_dict={"pwdLastSet": 133700000000000000}
        )

        class FakeConnection:
            result = {"result": 0}
            entries = [entry]
            bound = False
            last_instance = None

            def __init__(self, server, **kwargs):
                self.kwargs = kwargs
                type(self).last_instance = self

            def bind(self):
                self.bound = True
                return True

            def search(self, **kwargs):
                self.search_kwargs = kwargs
                return True

            def unbind(self):
                self.bound = False
                return True

        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "AD_SESSION_READER_USERNAME": r"IFTS\svc_ticketera_ldap",
            "AD_SESSION_READER_PASSWORD": "reader-test-password",
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection", FakeConnection):
            pwd_last_set = get_password_last_set("alice", config)

        self.assertEqual(pwd_last_set, "133700000000000000")
        self.assertEqual(FakeConnection.last_instance.kwargs["authentication"], NTLM)
        self.assertEqual(
            FakeConnection.last_instance.search_kwargs["attributes"], ["pwdLastSet"]
        )
        self.assertEqual(
            FakeConnection.last_instance.search_kwargs["search_filter"],
            "(sAMAccountName=alice)",
        )

    def test_refuses_to_send_simple_reader_credentials_over_plain_ldap(self):
        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "AD_SESSION_READER_USERNAME": "svc_ticketera_ldap@IFTS.local",
            "AD_SESSION_READER_PASSWORD": "reader-test-password",
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection") as connection:
            with self.assertRaisesRegex(ValueError, "sin cifrar"):
                get_password_last_set("alice", config)

        connection.assert_not_called()

    def test_invalid_credentials_return_none(self):
        class FakeConnection:
            result = {"result": 49}
            bound = False

            def __init__(self, server, **kwargs):
                pass

            def bind(self):
                return False

        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "ROLE_DN_MAP": ROLE_DN_MAP,
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection", FakeConnection):
            self.assertIsNone(authenticate_ad("alice", "wrong", config))

    def test_ldap_connection_failure_is_reported_as_ad_connection_error(self):
        class FakeConnection:
            bound = False

            def __init__(self, server, **kwargs):
                pass

            def bind(self):
                raise LDAPSocketOpenError("connection timed out")

        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "ROLE_DN_MAP": ROLE_DN_MAP,
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection", FakeConnection):
            with self.assertRaises(ADConnectionError):
                authenticate_ad("alice", "not-a-real-password", config)

    def test_authenticated_user_without_matching_role_is_distinguished(self):
        entry = SimpleNamespace(
            entry_attributes_as_dict={
                "sAMAccountName": "alice",
                "displayName": "Alice Example",
                "memberOf": [],
                "distinguishedName": [
                    "CN=Alice,OU=Users,DC=ifts,DC=local"
                ],
            }
        )

        class FakeConnection:
            result = {"result": 0}
            entries = [entry]
            bound = False

            def __init__(self, server, **kwargs):
                pass

            def bind(self):
                self.bound = True
                return True

            def search(self, **kwargs):
                return True

            def unbind(self):
                self.bound = False
                return True

        config = {
            "AD_DOMAIN": "IFTS.local",
            "AD_SERVER": "ldap://192.168.56.101",
            "AD_USE_SSL": False,
            "AD_BASE_DN": "DC=IFTS,DC=local",
            "ROLE_DN_MAP": ROLE_DN_MAP,
        }

        with patch("ad_auth.Server"), patch("ad_auth.Connection", FakeConnection):
            with self.assertRaises(ADRoleNotAssignedError):
                authenticate_ad("alice", "not-a-real-password", config)


if __name__ == "__main__":
    unittest.main()
