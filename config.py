"""Carga y valida la configuración de la aplicación desde el entorno y .env."""

import os
from datetime import time
from dotenv import load_dotenv

load_dotenv()


def _parse_time(value: str, fallback: time) -> time:
    """Convierte una hora HH:MM; si el valor es inválido usa el valor por defecto."""
    try:
        hours, minutes = map(int, value.strip().split(":"))
        return time(hour=hours, minute=minutes)
    except Exception:
        return fallback


class Config:
    """Ajustes de Flask, base SQLite, Active Directory y horario de acceso."""

    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("Configurá SECRET_KEY en el archivo .env antes de iniciar.")

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///ticketera.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Active Directory
    AD_SERVER = os.getenv("AD_SERVER", "ldap://192.168.56.101")
    AD_DOMAIN = os.getenv("AD_DOMAIN", "IFTS.local")
    AD_BASE_DN = os.getenv("AD_BASE_DN", "DC=IFTS,DC=local")
    AD_USE_SSL = os.getenv("AD_USE_SSL", "false").lower() == "true"

    # Mapeo por Grupos de AD (memberOf) O por Unidades Organizativas (distinguishedName)
    ROLE_DN_MAP = {
        # Si usás Grupos de Seguridad:
        "cn=ticketera_admin,ou=ticketera,dc=ifts,dc=local": "Admin",
        "cn=ticketera_operador,ou=ticketera,dc=ifts,dc=local": "Operador",
        "cn=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
        "cn=ticketera_consultor,ou=ticketera,dc=ifts,dc=local": "Consulta",
        "cn=ticketera_consulta,ou=ticketera,dc=ifts,dc=local": "Consulta",
        (
            "cn=ticketera_admin,ou=ticketera_admin,ou=ticketera,dc=ifts,dc=local"
        ): "Admin",
        "cn=gg_admin,ou=ticketera_admin,ou=ticketera,dc=ifts,dc=local": "Admin",
        (
            "cn=ticketera_operador,ou=ticketera_operador,ou=ticketera,dc=ifts,dc=local"
        ): "Operador",
        (
            "cn=ticketera_usuario,ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local"
        ): "Usuario",
        (
            "cn=ticketera_consultor,ou=ticketera_consultor,ou=ticketera,dc=ifts,dc=local"
        ): "Consulta",
        (
            "cn=ticketera_consulta,ou=ticketera_consulta,ou=ticketera,dc=ifts,dc=local"
        ): "Consulta",
        # Si ubicás los usuarios dentro de sub-OUs de OU=ticketera:
        "ou=ticketera_admin,ou=ticketera,dc=ifts,dc=local": "Admin",
        "ou=ticketera_operador,ou=ticketera,dc=ifts,dc=local": "Operador",
        "ou=ticketera_usuario,ou=ticketera,dc=ifts,dc=local": "Usuario",
        "ou=ticketera_consultor,ou=ticketera,dc=ifts,dc=local": "Consulta",
        "ou=ticketera_consulta,ou=ticketera,dc=ifts,dc=local": "Consulta",
    }

    # ACCESS_START y ACCESS_END se interpretan en la zona indicada en TIMEZONE.
    ACCESS_START = _parse_time(os.getenv("ACCESS_START", "08:00"), time(8, 0))
    ACCESS_END = _parse_time(os.getenv("ACCESS_END", "18:00"), time(18, 0))
    TIMEZONE = os.getenv("TIMEZONE", "America/Argentina/Buenos_Aires")