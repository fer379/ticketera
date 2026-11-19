from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from ldap3 import ALL, SUBTREE, Connection, Server
from ldap3.core.results import RESULT_INVALID_CREDENTIALS
from ldap3.utils.conv import escape_filter_chars


def _attribute_values(attributes: Mapping[str, Any], name: str) -> list[str]:
    value = attributes.get(name)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _resolve_role(
    attributes: Mapping[str, Any], role_dn_map: Mapping[str, str]
) -> str | None:
    normalized_map = {
        dn.strip().lower(): role for dn, role in role_dn_map.items()
    }

    group_roles = {
        normalized_map[member.strip().lower()]
        for member in _attribute_values(attributes, "memberOf")
        if member.strip().lower() in normalized_map
    }
    if len(group_roles) == 1:
        return next(iter(group_roles))
    if group_roles:
        return None

    user_dn = _attribute_values(attributes, "distinguishedName")
    if not user_dn:
        return None

    ou_roles = {
        role
        for dn, role in normalized_map.items()
        if dn.startswith("ou=")
        and user_dn[0].strip().lower().endswith(f",{dn}")
    }
    return next(iter(ou_roles)) if len(ou_roles) == 1 else None


def authenticate_ad(
    username: str, password: str, config: Mapping[str, Any]
) -> dict[str, str] | None:
    username = username.strip()
    if not username or not password:
        return None

    domain = config["AD_DOMAIN"].strip()
    if "\\" in username:
        bind_user = username
        search_username = username.rsplit("\\", 1)[1]
        search_filter = (
            f"(sAMAccountName={escape_filter_chars(search_username)})"
        )
    elif "@" in username:
        bind_user = username
        search_username = username.split("@", 1)[0]
        search_filter = (
            "(|"
            f"(sAMAccountName={escape_filter_chars(search_username)})"
            f"(userPrincipalName={escape_filter_chars(username)}))"
        )
    else:
        bind_user = f"{username}@{domain}"
        search_username = username
        search_filter = (
            f"(sAMAccountName={escape_filter_chars(search_username)})"
        )

    server_url = config["AD_SERVER"].strip()
    if "://" not in server_url:
        server_url = f"ldap://{server_url}"
    parsed_url = urlsplit(server_url)
    if parsed_url.scheme not in ("ldap", "ldaps") or not parsed_url.hostname:
        raise ValueError("AD_SERVER debe ser un host o una URL ldap:// o ldaps://.")

    use_ssl = config["AD_USE_SSL"] or parsed_url.scheme == "ldaps"
    server = Server(
        parsed_url.hostname,
        port=parsed_url.port or (636 if use_ssl else 389),
        use_ssl=use_ssl,
        get_info=ALL,
    )
    connection = Connection(
        server,
        user=bind_user,
        password=password,
        auto_bind=False,
        raise_exceptions=False,
    )

    try:
        if not connection.bind():
            if connection.result.get("result") == RESULT_INVALID_CREDENTIALS:
                return None
            message = connection.result.get("message") or "respuesta LDAP sin detalle"
            raise RuntimeError(f"No se pudo autenticar contra Active Directory: {message}")

        search_ok = connection.search(
            search_base=config["AD_BASE_DN"],
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "displayName",
                "cn",
                "distinguishedName",
                "memberOf",
            ],
        )
        if not search_ok and connection.result.get("result") != 0:
            message = connection.result.get("message") or "respuesta LDAP sin detalle"
            raise RuntimeError(f"No se pudo buscar el usuario en Active Directory: {message}")
        if len(connection.entries) != 1:
            return None

        attributes = connection.entries[0].entry_attributes_as_dict
        role = _resolve_role(attributes, config["ROLE_DN_MAP"])
        account_name = _attribute_values(attributes, "sAMAccountName")
        if not role or not account_name:
            return None

        display_name = (
            _attribute_values(attributes, "displayName")
            or _attribute_values(attributes, "cn")
            or account_name
        )[0]
        return {
            "username": account_name[0],
            "display_name": display_name,
            "role": role,
        }
    finally:
        if connection.bound:
            connection.unbind()
