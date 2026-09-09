# FashionForge CTF Lab — OWASP API Security Top 10

Laboratorio **red team** de seguridad de APIs basado en **FashionForge**, una plataforma de e-commerce de moda **deliberadamente vulnerable**. Entrena el **OWASP API Security Top 10 (2023)** con técnicas ofensivas reales en **4 laboratorios progresivos** (Fácil → Media → Compleja) y **26 retos CTF** (R01–R26) con flags `FH{...}`.

> ⚠️ **Proyecto educativo/pentest**: corre solo en un entorno aislado (Docker local). No despliegues este código en producción: está lleno de vulnerabilidades a propósito.

## Estructura

| Ruta | Contenido |
|---|---|
| `app.py` | API principal vulnerable (FashionForge) en `:5000` |
| `oauth_server.py` | Servidor OAuth/OIDC vulnerable en `:5001` |
| `graphql_vuln.py` | Motor GraphQL inseguro (`eval`/`exec`), endpoint `/graphql/query` |
| `jwt_utils.py`, `jwt_custom.py` | Validación JWT con secrets conocidos/código por defecto |
| `templates/`, `templates_oauth/` | Frontends web (login, upload, admin, AI tools…) |
| `docs/labs/` | **Documentación principal**: índice + mapeo OWASP + 4 laboratorios con los 26 retos |

## Arranque y reseteo

```bash
docker compose up -d --build        # api :5000 + oauth :5001
docker compose logs -f api          # logs

# reset completo (borra BD, uploads, sesiones y resiembra):
docker compose down
rm -rf instance/fashion.db uploads/* session_data/*
docker compose up -d --build
```

## Documentación

La guía completa está en [`docs/labs/README.md`](docs/labs/README.md):

- **Arquitectura**, cuentas y productos seed (credenciales por defecto = fuga API2 por diseño).
- **Mapeo OWASP API Top 10 (2023)** a los vectores reales del código (todos verificados en vivo).
- **4 laboratorios progresivos** por dificultad: Reconocimiento/Auth (Lab 1) → Autorización (Lab 2) → Inyecciones/RCE (Lab 3) → Lógica de negocio/OAuth/OIDC/Cadena (Lab 4).
- **26 retos** (R01–R26) con prerequisitos, payloads `curl` verificados, prueba de éxito, flag y remediación.
- **Mapas de equivalencia** de la reordenación por dificultad (numeración nueva vs. antigua).

Los retos se cursan **en orden y por dificultad creciente**; cada uno documenta sus `**Prerequisitos**`.

## Pila

Python 3.13 · Flask · SQLAlchemy/SQLite · `gunicorn --workers 4` · python-jose/pyjwt · GraphQL · PyJWT · Docker Compose