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

Para cambiar el horario de acceso, editá en `.env`:

```dotenv
ACCESS_START=08:00
ACCESS_END=18:00
TIMEZONE=America/Argentina/Buenos_Aires
```

Usá el formato de 24 horas `HH:MM`. `ACCESS_START` es la hora de apertura y
`ACCESS_END` la hora de cierre. Después de guardar `.env`, reiniciá la aplicación.
`.env.example` muestra esos valores como referencia para una instalación nueva;
el archivo que usa la aplicación es `.env`.

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
real del dominio; actualizá `ROLE_DN_MAP` si cambia. El grupo
`GG_Consultores` ubicado directamente en `OU=ticketera` asigna el rol Consulta.

`AD_USE_SSL=true` habilita LDAPS (puerto 636 por defecto); el certificado del
servidor debe ser confiable para el equipo que ejecuta la aplicación.

Si el login indica que no pudo conectar con Active Directory, comprobá que la
VM esté encendida, que `AD_SERVER` tenga su IP actual y que el equipo pueda
alcanzar el puerto LDAP configurado (389 sin SSL o 636 con LDAPS).

El acceso se restringe por defecto a las 08:00–18:00, según `TIMEZONE`.
Para una prueba fuera de ese horario, ajustá temporalmente `ACCESS_START` o
`ACCESS_END` en `.env` y restauralos después.

### Cierre de sesiones al cambiar la contraseña de AD

La sesión web no contiene la contraseña del usuario. Para detectar cambios
mientras la aplicación está abierta, Ticketera guarda el valor de `pwdLastSet`
al iniciar sesión y lo compara cada 15 segundos con Active Directory. Si cambia,
cierra la sesión y vuelve al login; también la cierra si no puede consultar AD.

Para habilitarlo, creá **una sola cuenta técnica normal** en AD, por ejemplo
`svc_ticketera_ldap`. No es una cuenta para las personas que usan la ticketera:
no necesita pertenecer a Domain Admins ni a grupos de administración. Solo debe
poder leer `pwdLastSet` de los usuarios de la Ticketera. En ADUC, esto se
configura en los permisos de lectura de la OU que contiene a esos usuarios; la
pestaña **Remote Control** es de Escritorio remoto y no interviene. No compartas
la contraseña de esta cuenta ni la guardes en el repositorio.

En `.env`, cargá esa única cuenta y su contraseña:

```dotenv
AD_SESSION_READER_USERNAME=IFTS\svc_ticketera_ldap
AD_SESSION_READER_PASSWORD=una-clave-larga-de-la-cuenta-tecnica
SESSION_PASSWORD_CHECK_INTERVAL_SECONDS=15
```

El formato `DOMINIO\usuario` usa autenticación NTLM para la cuenta técnica.
Si el servidor tiene LDAPS configurado y su certificado es confiable, también
podés usar su UPN (`svc_ticketera_ldap@IFTS.local`) con `AD_SERVER=ldaps://...`
y `AD_USE_SSL=true`. Reiniciá la aplicación una vez después de configurar `.env`;
no hace falta reiniciar el navegador. El control se ejecuta en cada pestaña
abierta y vuelve a comprobar la sesión al regresar a una pestaña en segundo
plano. El intervalo permitido es de 5 a 300 segundos.

No uses un UPN con `SIMPLE` en LDAP sin TLS: la aplicación lo rechaza para la
cuenta técnica porque expondría su contraseña en la red. LDAPS es la opción
recomendada también para la autenticación de los usuarios de la Ticketera.

Si las dos variables de la cuenta técnica están vacías, la aplicación sigue
permitiendo el login normal, pero avisa que el cierre automático no está activo.
Si solo se completa una, la aplicación informa el error de configuración al
iniciar.

## Funcionalidad y permisos

| Rol de AD | Permisos en la aplicación |
| --- | --- |
| Admin | Consulta y gestiona todos los tickets, crea, asigna, actualiza y elimina. |
| Operador | Consulta todos los tickets, crea y actualiza estado, prioridad, responsable e historial. |
| Usuario | Crea y consulta sus tickets, y agrega observaciones al historial; no cambia estado, prioridad ni responsable. |
| Consulta | Consulta todos los tickets y exporta reportes; no puede modificarlos. |

La pantalla principal muestra una descripción y acciones acordes al rol. El
listado de Usuario se limita a sus propias solicitudes. Sus observaciones se
registran con fecha y autor en el historial, sin reabrir ni cambiar el estado;
el equipo de soporte debe revisar el comentario y decidir qué acción tomar.
En el panel, las tarjetas de estado filtran los tickets sin recargar la página.
Solo Admin ve la opción de eliminación en el listado y en la pantalla de
gestión; ambas solicitan confirmación antes de borrar definitivamente el
ticket.

## Persistencia, fechas y seguridad

- Los tickets e historiales se persisten en SQLite (`ticketera.db`).
- Las fechas se guardan en UTC y se muestran/exportan en hora argentina
  (`TIMEZONE`, por defecto `America/Argentina/Buenos_Aires`, GMT-3).
- Los formularios validan campos y longitudes; las operaciones de escritura
  requieren un token CSRF.
- Las consultas de base usan SQLAlchemy ORM y filtros parametrizados.
- `SECRET_KEY` se configura en `.env`; no publiques ni compartas ese archivo.
- Para redes no aisladas, habilitá LDAPS y verificá la confianza del certificado
  del controlador de dominio.

## Mapa sencillo del código

- `app.py`: conecta las piezas y define las páginas y acciones web. También
  controla el horario, las sesiones, los roles, la validación de formularios y
  la descarga CSV.
- `ad_auth.py`: se comunica con Active Directory, comprueba el usuario y busca
  su rol.
- `config.py`: lee `.env` y reúne la configuración de Flask, AD, SQLite y horario.
- `models.py`: describe cómo se guardan un ticket y sus cambios en SQLite.
- `init_db.py`: prepara las tablas y, si la base está vacía, agrega ejemplos.
- `.env.example`: plantilla de configuración para crear `.env` en una instalación nueva.
- `.env`: configuración local activa; contiene datos sensibles y no debe compartirse.
- `.gitignore`: evita incluir el entorno virtual, la base local y `.env` al compartir el código.
- `templates/base.html`: marco visual compartido, navegación y mensajes.
- `templates/auth/login.html`: ingreso con cuenta de AD.
- `templates/tickets/list.html`: panel, resumen y búsqueda de tickets.
- `templates/tickets/_results.html`: tabla reutilizada por el panel y sus filtros dinámicos.
- `templates/tickets/new.html`: formulario para registrar una solicitud.
- `templates/tickets/detail.html`: detalle, historial y acciones permitidas por rol.
- `static/css/style.css`: estilos y transiciones compartidos.
- `static/js/script.js`: interacciones del navegador, filtros sin recarga y avisos temporales.
- `requirements.txt`: paquetes de Python que necesita la aplicación.
- `tests/`: pruebas automáticas de autenticación, permisos, fechas y formularios.

La base SQLite se crea en `instance/ticketera.db` cuando se ejecuta la aplicación.

### Cómo funciona una solicitud

1. El usuario inicia sesión y `ad_auth.py` valida sus credenciales en AD.
2. `config.py` relaciona el grupo o la OU del usuario con uno de los cuatro roles.
3. `app.py` verifica el horario y limita las acciones según el rol.
4. `models.py` y SQLAlchemy guardan tickets e historial en `ticketera.db`.
5. Las plantillas muestran las pantallas; los reportes se descargan como CSV.