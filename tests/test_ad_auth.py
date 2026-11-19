import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ad_auth import _resolve_role, authenticate_ad


ROLE_DN_MAP = {
    "cn=ticketera_admin,ou=ticketera_admin,ou=ticketera,dc=ifts,dc=local": "Admin",
    "cn=ticketera_usuario,ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
    "ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
}


class AdAuthTests(unittest.TestCase):
    def test_resolves_nested_group_membership(self):
        attributes = {
            "memberOf": [
                "CN=ticketera_admin,OU=ticketera_admin,OU=ticketera,DC=ifts,DC=local"
            ]
        }

        self.assertEqual(_resolve_role(attributes, ROLE_DN_MAP), "Admin")

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
            upn_user = authenticate_ad(
                "alice@IFTS.local", "not-a-real-password", config
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
            FakeConnection.last_instance.kwargs["user"], "alice@IFTS.local"
        )
        self.assertEqual(upn_user["username"], "alice")
        self.assertEqual(
            FakeConnection.last_instance.search_kwargs["search_filter"],
            "(|(sAMAccountName=alice)(userPrincipalName=alice@IFTS.local))",
        )

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


if __name__ == "__main__":
    unittest.main()
