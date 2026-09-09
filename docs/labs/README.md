# FashionForge CTF Lab — OWASP API Top 10 (2023) con enfoque red team

Laboratorio **red team** de seguridad de APIs basado en **FashionForge**, una plataforma de e-commerce de moda deliberadamente vulnerable (evolucionada del antiguo "Automobile API", luego "Fashion API"). El objetivo es entrenar **OWASP API Security Top 10 (2023)** practicando **técnicas ofensivas reales** (reconocimiento, BOLA/IDOR, mass assignment, BFLA, SQLi/RCE, GraphQL, OAuth/OIDC, prompt injection) a lo largo de **4 laboratorios** red team, con retos CTF documentados y web de flags.

> **Filosofía red team**: cada laboratorio simula una fase del ciclo de un penetration test (`recon → explotación → escalada → encadenado`). Se asume mindset ofensivo: primero descubrir superficie, luego vulnerabilidades, y finalmente construir la cadena de explotación. Todo lo documentado se probó y verificó en vivo contra el objetivo corriendo.

---

## 1. Arquitectura del objetivo

| Servicio | URL | Región |
|---|---|---|
| **API principal (FashionForge)** | `http://localhost:5000` | `api-server` (Docker) |
| **Servidor OAuth/OIDC** | `http://localhost:5001` | `oauth-server` (Docker) |
| **GraphQL endpoint** | `POST /graphql/query` | dentro de la API |
| **Swagger / OpenAPI** | `http://localhost:5000/api/docs` | documentación de superficie |

**Recurso**: `fashion.db` (SQLite, compartida entre `api-server` y `oauth-server`).

### Cuentas seed (credenciales por defecto = fuga API2)

| Usuario | Contraseña | Rol | ID |
|---|---|---|---|
| `admin` | `admin123` | admin | 1 |
| `superadmin` | `super123` | admin | 4 |
| `john` | `password123` | usuario | 2 |
| `jim` | `password123` | usuario | 3 |

> Los IDs son **enteros secuenciales** — útil para BOLA/IDOR.

### Productos seed

| ID | Nombre | Marca | Precio | Propietario (id) |
|---|---|---|---|---|
| 1 | Classic Tee | Essential Wear | $25.00 | john (2) |
| 2 | Skinny Jeans | Denim Co | $60.00 | jim (3) |
| 3 | Leather Jacket | Moto Style | $120.00 | john (2) |
| 4 | Running Sneakers | Stride | $85.00 | jim (3) |

---

## 2. Instalación / arranque del laboratorio

```bash
cd /home/poncio/cwl/api-lab-class/AutoAPI
docker compose up -d --build          # construye y levanta api + oauth
docker compose logs -f api            # logs de la API (debug)
```

- Reseteo completo del estado (borra DB, uploads y vuelve a sembrar):
  ```bash
  docker compose down
  rm -rf instance/fashion.db uploads/* session_data/*
  docker compose up -d --build
  ```
- Prueba rápida de que está viva:
  ```bash
  curl -s http://localhost:5000/login  # 200
  curl -s http://localhost:5001/health # 200
  ```

### Herramientas recomendadas
- **Burp Suite** / **ZAP** (proxy + repeater)
- `curl` + `jq` (o `python3 -m json.tool`)
- Postman / Insomnia
- `ffuf` o `gobuster` (enumeración)
- Un editor de JWT (jwt.io con secret conocido) o `pyjwt`

### Obtener un JWT normal
```bash
JWT=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | jq -r '.access_token')
```

---

## 3. Mapeo OWASP API Top 10 (2023) → Vulnerabilidades reales de la app

> Todos los vectores verificados manualmente contra el código (`app.py`, `jwt_utils.py`, `jwt_custom.py`, `oauth_server.py`, `graphql_vuln.py`) y probados en vivo.

### API1 — Broken Object Level Authorization (BOLA/IDOR)

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | Leer detalles de orden ajena (además **auto-crea** la orden si no existe) | `GET /api/orders/<id>/details` | JWT (cualquiera) |
| 2 | Exponer owner_id + email del dueño de cualquier producto | `GET /api/products/<id>/owner-info` | **público** |
| 3 | Transferir propiedad de cualquier producto a cualquier usuario | `POST /api/products/<id>/transfer-ownership` | **público** |
| 4 | Cambiar estado de orden ajena; `refunded` reembolsa y libera el producto | `PUT /api/orders/<id>/status` | **público** |
| 5 | Leer perfil completo (password_hash, balance) de cualquier usuario | `GET /api/users/<id>` | JWT (cualquiera) |
| 6 | Lookup de usuarios por username/email + 5 más recientes (password_hash) | `POST /api/users/info` | **público** |
| 7 | Transferencia de fondos indicando el **origen** por username ajena (spoofing) | `POST /api/payments/transfer` | JWT |
| 8 | Ídem + (race teórico — no reproducible en SQLite+sync) | `POST /api/payments/transfer-username` | JWT |

### API2 — Broken Authentication

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | **JWT firmado con secret conocido/fallback** → impersonar admin (`sub:1, admin:true`) | cualquier `/api/...` con Bearer | — |
| 2 | Cookie `jwt_token` sin `HttpOnly` y `Secure=False` | en login web | — |
| 3 | Basic Auth sin rate limit → fuerza bruta ilimitada | `POST /api/auth/basic-login` | — |
| 4 | Logout no revoca tokens; refresh emite nuevos indefinidamente | `POST /api/auth/logout`, `/api/auth/refresh-token` | — |
| 5 | **OAuth**: secret HS256 expuesto en `/oauth/jwks` | `GET http://localhost:5001/oauth/jwks` | público |
| 6 | **OAuth**: scope `admin` escalada → token del primer admin | flujo `/oauth/authorize` scope=`openid admin` | — |
| 7 | **OIDC vulnerable**: id_token verificado con `verify_signature=False` | `/oidc/callback_vuln` | — |
| 8 | **OAuth**: redirect_uri no validado contra whitelist (open redirect) | `/oauth/authorize` | — |

### API3 — Broken Object Property Level Authorization (Mass Assignment)

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | Registro con `is_admin:true` y/o `balance` arbitrario | `POST /api/auth/register` / `POST /register` | público |
| 2 | Crear producto sin validar precio (0.01, negativo) | `POST /api/secure/products` | JWT |

### API4 — Unrestricted Resource Consumption

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | Rate limit 5/min **en memoria por-worker** (4 workers de gunicorn; no compartido, resetea en 60s) → tasa sostenida ≫5/min | `GET /api/products` (ruta con limit) | JWT |
| 2 | Ruta duplicada `/api/products` sin limit **ensombrecida** por Flask (solo sirve la primera registrada) → no bypasea, pero documenta el desorden | `GET /api/products` | JWT |
| 3 | SSE con `count` arbitrario (DoS) | `GET /api/stream/product-feed?count=99999999` | JWT |
| 4 | Brute force: límites altos y por-IP (`/api/auth/login` 100/min) + Basic sin límite | `POST /api/auth/login` | — |

### API5 — Broken Function Level Authorization

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | Promover a admin a cualquiera, **sin autenticar** | `POST /api/admin/promote` | **público** |
| 2 | Borrar cualquier usuario (incluido admin) | `DELETE /api/secure/delete-user/<id>` | JWT (sin rol) |
| 3 | Stats/Users/Orders "admin" — rotos: dependen de decorador que no tienen → endpoint inaccesible (info) | `GET /api/admin/*` | (403 siempre) |

### API6 — Unrestricted Access to Sensitive Business Flows

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | **Manipulación de precio**: `price_override` (clamp min $1), `discount_code` (SAVE10/50/99/FREE), `special_offer` (si >1000, divide a la mitad) — vía **sesión web** (Flask-Login) | `POST /api/products/<id>/purchase` | sesión web |
| 2 | **Transferencia desde cuenta ajena**: el body `username` define el **origen** sin verificarlo (spoofing); race condition teórico (no reproducible en SQLite+sync) | `POST /api/payments/transfer-username` | JWT |

### API7 — Server Side Request Forgery (SSRF)

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | Fetch de URL arbitraria, `verify=False`, acceso a red Docker | `POST /api/network/fetch` (`{"url":"..."}`) | JWT |
| 2 | `transactions_export`: también dispara `cmd` con runner bash/python | `GET /transactions/export?...` | **público** |

### API8 — Security Misconfiguration

| # | Explotación | Ubicación |
|---|---|---|
| 1 | `debug=True` → debugger interactivo Werkzeug | `app.py` (`__main__`) |
| 2 | Secret keys hardcodeadas (app, JWT fallback, OAuth, session) | `config.py`, `app.py`, `jwt_utils.py`, `oauth_server.py` |
| 3 | Cookies sin `Secure`, `jwt_token` sin `HttpOnly` | login/callback |
| 4 | Swagger/OpenAPI completo sin auth | `GET /api/docs` |
| 5 | `/debug/verify-database` restringido por IP pero **bypasseable con `X-Forwarded-For: 127.0.0.1`** | `GET /debug/verify-database` |
| 6 | OAuth `/debug/users`, `/debug/test-password` públicos | `http://localhost:5001/debug/*` |

### API9 — Improper Inventory Management
Mitigado / N/A: es un lab. Se aprovecha la versión documentada en Swagger y las APIs antiguas marcadas `vulnerable`.

### API10 — Unsafe Consumption of APIs

| # | Explotación | Endpoint | Auth |
|---|---|---|---|
| 1 | **Prompt injection** → actualizar balance real de usuarios | `POST /api/ai/chatbot` | JWT |
| 2 | Ídem vía generación de descripción de producto | `POST /api/ai/generate` | JWT |
| 3 | XSS reflejado en `ai_tools.html` (innerHTML sin escapar) para robar cookie `jwt_token` | `POST /api/ai/chatbot` + UI | — |

### Extras (también explotables, fuera del Top 10)

| Tipo | Explotación | Endpoint | Auth |
|---|---|---|---|
| SQLi | `username LIKE '%<q>%'` — extrae password_hash | `GET /api/users/search?q=' OR '1'='1` | JWT |
| Command Injection | `subprocess.check_output(sku, shell=True)` → RCE | `POST /api/automobile/sku-lookup` (`{"sku":"id"}`) | JWT |
| Command Injection 2 | `/transactions/export` ejecuta `cmd` (bash/python) | `GET /transactions/export?filename=...&cmd=id&runner=bash` | **público** |
| Path Traversal | descarga de archivos con `..` | `GET /api/files/../../../etc/passwd` | JWT |
| Path Traversal 2 | lectura de archivos del nodo | `GET /transactions/export?filename=../../etc/passwd` | **público** |
| File upload | subida sin validación → webshell | `POST /api/products/<id>/upload`, `POST /api/upload` | JWT |
| GraphQL RCE | `exec(...)`, `os.system`, `open().read()`, introspection, filtros eval | `POST /graphql/query` | **público** |
| XSS almacenado | `image_url` sin sanitizar en plantillas | create product / mass assignment | — |

---

## 4. Formato de retos y sistema de flags

Cada reto entrega una **flag** verificable del formato:

```
FH{<slug-del-reto>}
```

Ejemplo: `FH{sqli-users-search}`. Para cada reto se indica:
- **OWASP** (categoría que cubre)
- **Objetivo** (qué se debe comprometer)
- **Dificultad** (Fácil/Media/Compleja)
- **Paso a paso** con payloads `curl` verificados
- **Prueba de éxito** (respuesta esperada)
- **Flag**
- **Remediación** real (cómo se arregla en producción)

> Los payloads de esta guía fueron **ejecutados y verificados** contra el lab corriendo. Si un paso no responde igual, revisa el estado del entorno (cuentas compradas por las que el producto ya no esté disponible, balance cambiado, etc.) o resetéalo con el comando de la sección 2.

---

## 5. Campaña red team en 4 laboratorios

Los laboratorios se cursan **en orden y por dificultad creciente**: cada uno es un escalón del nivel anterior. Dentro de cada laboratorio, los retos (R01–R26) también van de menor a mayor dificultad; **empieza siempre por el reto de menor número** de su laboratorio. Varios retos son **prerequisito** de otros (se indica en cada reto con `**Prerequisitos**`).

| Laboratorio | Fase del ciclo red team | Dificultad | Categorías OWASP | Retos |
|---|---|---|---|---|
| [Laboratorio 1](laboratorio-1.md) | Reconocimiento y At. de autenticación (broadening) | **Fácil** | API2, API8, API10 | R01–R06 |
| [Laboratorio 2](laboratorio-2.md) | Explotación de autorización (objetos, escalada) | **Fácil–Media** | API1, API3, API5 | R07–R12 |
| [Laboratorio 3](laboratorio-3.md) | Ejecución y compromiso de host (inyecciones/RCE) | **Media** | API7 + extras | R13–R19 |
| [Laboratorio 4](laboratorio-4.md) | Lógica de negocio, confianza (OAuth/OIDC) y encadenado | **Media–Compleja** | API4, API6, API10 | R20–R26 |

**Dependencias clave entre retos** (para no atascarte):

```
R01  → R02  → R03 → R04            (Lab 1: entrar y entender tokens)
R02  → R05  (secret/JWT forjado; R24 lo fuga de forma "oficial")
...
R07, R08, R09, R10          (Lab 2: acceso a objetos + escalada)
R11 (necesita R08+R09) · R12 (necesita R07+R08)
...
R15 → R17 → R18            (Lab 3: leer → subir shell → RCE export)
R14 → R19                  (mismo motor GraphQL)
...
R24 → R25                  (Lab 4: OAuth → OIDC)
R26  (Boss) → usa R05, R06, R07, R08, R09, R10, R20
```

**Total: 26 retos** con solución paso a paso. Al final del **Laboratorio 4** hay una **guía de remediación consolidada** (perspectiva defensiva tras el ataque) y un **reto de cadena de explotación completa**. En un engagement red team, este documento juega ambos bandos: la guía de los laboratorios (ataque) y la remediación (defensa).

### Mapas de equivalencia tras la reordenación por dificultad

> En esta reorganización se **reenumeraron los retos** para que la secuencia R01→R26 sea progresiva. Equivalencias con la numeración antigua:

| Actual | Antes | Actual | Antes |
|---|---|---|---|
| R04 | (antiguo R05) | R14 | (antiguo R16) |
| R05 | (antiguo R04) | R15 | (antiguo R18) |
| R09 | (antiguo R11) | R16 | (antiguo R14) |
| R10 | (antiguo R12) | R17 | (antiguo R19) |
| R11 | (antiguo R09) | R18 | (antiguo R15) |
| R12 | (antiguo R10) | R19 | (antiguo R17) |
| R13 | (antiguo R13) | R21 | (antiguo R23) |
| — | — | R23 | (antiguo R21) |

Los retos R01, R02, R03, R06, R07, R08, R20, R22, R24, R25 y R26 conservan su número.

---

## 6. Índice de archivos de esta documentación

| Archivo | Contenido |
|---|---|
| `docs/labs/README.md` | Este archivo (índice + mapeo OWASP) |
| `docs/labs/laboratorio-1.md` | Laboratorio 1 — Reconocimiento y Autenticación |
| `docs/labs/laboratorio-2.md` | Laboratorio 2 — Autorización (BOLA/Mass Assignment/BFLA) |
| `docs/labs/laboratorio-3.md` | Laboratorio 3 — Inyecciones y RCE |
| `docs/labs/laboratorio-4.md` | Laboratorio 4 — Lógica de negocio, OAuth y Prompt injection |