# Ticketera AD

## Requisitos

- Python 3.10 o posterior.
- Acceso de red desde esta computadora al servidor de Active Directory.
- Un usuario de AD incluido en un grupo o una OU configurados en `ROLE_DN_MAP`
  dentro de `config.py`.

## Preparación en Windows

Desde esta carpeta, en PowerShell:

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Editá `.env`: establecé una `SECRET_KEY` aleatoria (por ejemplo,
`python -c "import secrets; print(secrets.token_hex(32))"`), verificá el host LDAP,
dominio, DN base y horario. No compartas ni publiques `.env`.

Inicializá la base y ejecutá la aplicación:

```powershell
python init_db.py
python app.py
```

La aplicación escucha en el puerto 5000. Para acceder desde otra computadora,
permití ese puerto en el firewall del servidor y usá la IP o el nombre del
servidor en la URL.

## Asignación de roles

`authenticate_ad` autentica con el usuario y contraseña de AD, busca la cuenta
por `sAMAccountName` y asigna un rol a partir de una pertenencia directa
(`memberOf`) o de la OU donde está ubicado el usuario. Se acepta el nombre
`sAMAccountName` o el UPN del usuario. Los DN deben coincidir con la estructura
real del dominio; actualizá `ROLE_DN_MAP` si cambia.

`AD_USE_SSL=true` habilita LDAPS (puerto 636 por defecto); el certificado del
servidor debe ser confiable para el equipo que ejecuta la aplicación.

El acceso se restringe por defecto a las 08:00–18:00, según `TIMEZONE`.
Para una prueba de login fuera de ese horario, ajustá temporalmente `ACCESS_END`
en `.env` y restauralo después.