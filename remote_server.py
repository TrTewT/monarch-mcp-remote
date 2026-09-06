"""Passerelle HTTP distante pour robcerda/monarch-mcp-server.

Pourquoi ce fichier existe
--------------------------
Le serveur amont (robcerda/monarch-mcp-server) est concu pour tourner en
*stdio* sur une machine personnelle : le client MCP lance le processus et lui
parle par l'entree/sortie standard. Ce mode est inutilisable a distance, et il
suppose une session Monarch deja enregistree dans le trousseau du systeme.

Ce module ajoute les trois briques qui manquent pour un hebergement distant :

1. ``bootstrap_session()`` : recree la session Monarch a partir d'une variable
   d'environnement, puisqu'un conteneur n'a ni trousseau ni terminal.
2. Une passerelle d'authentification : le serveur amont n'en a aucune, et un
   endpoint MCP financier sans authentification est ouvert a quiconque connait
   l'URL.
3. Le transport *streamable HTTP*, qui est celui que Claude, Codex et l'API
   OpenAI savent consommer a distance.

Deux facons de s'authentifier, parce que les clients ne se valent pas :

- En-tete ``Authorization: Bearer <MCP_AUTH_TOKEN>`` pour les clients qui
  acceptent des en-tetes personnalises (Codex, API, scripts).
- Segment secret dans l'URL : ``https://host/s/<MCP_AUTH_TOKEN>/mcp`` pour les
  clients qui n'acceptent qu'une URL (connecteurs personnalises Claude).

Les deux comparent le secret en temps constant. Le secret d'acces au serveur
est volontairement distinct du jeton de session Monarch : le faire fuiter ne
donne pas acces au compte Monarch en dehors des outils exposes, et il se
revoque en changeant une seule variable d'environnement.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import stat
from pathlib import Path
from typing import Any

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("monarch-mcp-remote")

# --------------------------------------------------------------------------
# 1. Reconstitution de la session Monarch
# --------------------------------------------------------------------------

TOKEN_DIR = Path.home() / ".monarch-mcp-server"
TOKEN_FILE = TOKEN_DIR / "token"


def bootstrap_session() -> str:
    """Ecrit la session Monarch attendue par le serveur amont.

    Le serveur amont lit sa session via ``SecureMonarchSession``, qui essaie
    le trousseau puis se rabat sur ``~/.monarch-mcp-server/token``. Dans un
    conteneur il n'y a pas de trousseau : on ecrit donc directement le
    fichier de repli, dans le format JSON exact que ``_parse_session_blob``
    sait relire.

    Trois entrees possibles, par ordre de priorite :

    - ``MONARCH_SESSION_JSON`` : le blob complet, tel que produit par
      ``login_setup.py`` (mode cookie ou mode jeton). C'est le mode le plus
      robuste, notamment parce qu'il transporte le ``device_uuid``.
    - ``MONARCH_COOKIE`` : la chaine d'en-tete Cookie copiee depuis une
      session navigateur Monarch (mode cookie, contourne le CAPTCHA).
    - ``MONARCH_TOKEN`` (+ ``MONARCH_DEVICE_UUID`` optionnel) : le jeton de
      session simple. Monarch attend en principe le meme ``device-uuid`` que
      celui presente a la connexion ; si le jeton est refuse, c'est la
      premiere piste a verifier.
    """
    raw_blob = os.environ.get("MONARCH_SESSION_JSON", "").strip()
    cookie_string = os.environ.get("MONARCH_COOKIE", "").strip()
    token = os.environ.get("MONARCH_TOKEN", "").strip()
    device_uuid = os.environ.get("MONARCH_DEVICE_UUID", "").strip()

    if raw_blob:
        try:
            blob = json.loads(raw_blob)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"MONARCH_SESSION_JSON n'est pas du JSON valide : {exc}"
            ) from exc
        source = "MONARCH_SESSION_JSON"
    elif cookie_string:
        cookies: dict[str, str] = {}
        for part in cookie_string.split(";"):
            if "=" in part:
                key, _, value = part.strip().partition("=")
                cookies[key.strip()] = value.strip()
        if not cookies:
            raise SystemExit("MONARCH_COOKIE ne contient aucun cookie exploitable.")
        blob = {"auth_mode": "cookie", "cookies": cookies}
        if token:
            blob["token"] = token
        if device_uuid:
            blob["device_uuid"] = device_uuid
        source = "MONARCH_COOKIE"
    elif token:
        blob = {"auth_mode": "token", "token": token}
        if device_uuid:
            blob["device_uuid"] = device_uuid
        source = "MONARCH_TOKEN"
    else:
        raise SystemExit(
            "Aucune session Monarch fournie. Definis MONARCH_SESSION_JSON, "
            "MONARCH_COOKIE ou MONARCH_TOKEN dans l'environnement."
        )

    TOKEN_DIR.mkdir(parents=True, exist_ok=True, mode=stat.S_IRWXU)
    try:
        TOKEN_DIR.chmod(stat.S_IRWXU)
    except OSError:
        pass
    # Ouverture avec le mode explicite : ecrire puis chmod laisserait une
    # fenetre pendant laquelle le fichier est lisible par tout le conteneur.
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(blob))

    logger.info(
        "Session Monarch reconstituee depuis %s (auth_mode=%s) -> %s",
        source,
        blob.get("auth_mode"),
        TOKEN_FILE,
    )
    return str(blob.get("auth_mode", "token"))


# La session doit exister avant que les modules amont ne soient importes :
# ``secure_session`` est instancie au moment de l'import et sonde le stockage.
AUTH_MODE = bootstrap_session()

from mcp.server.transport_security import (  # noqa: E402
    TransportSecuritySettings,
)
from monarch_mcp_server.app import mcp  # noqa: E402
from monarch_mcp_server.read_only import is_read_only  # noqa: E402
from starlette.responses import JSONResponse, Response  # noqa: E402
from starlette.routing import Route  # noqa: E402

# --------------------------------------------------------------------------
# 2. Passerelle d'authentification
# --------------------------------------------------------------------------

MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "").strip()
if not MCP_AUTH_TOKEN:
    raise SystemExit(
        "MCP_AUTH_TOKEN est obligatoire. Sans lui, l'endpoint MCP serait "
        "ouvert a quiconque connait l'URL — exactement le defaut de "
        "l'ancien serveur. Genere-le avec : python -c "
        "\"import secrets; print(secrets.token_urlsafe(32))\""
    )
if len(MCP_AUTH_TOKEN) < 24:
    raise SystemExit("MCP_AUTH_TOKEN trop court : 32 caracteres minimum.")

MCP_PATH = "/mcp"
SECRET_PREFIX = f"/s/{MCP_AUTH_TOKEN}"
PUBLIC_PATHS = {"/healthz", "/"}

# --------------------------------------------------------------------------
# 1 bis. Retrait cible d'outils
# --------------------------------------------------------------------------
#
# Le mode lecture seule amont est tout ou rien : soit les 49 outils, soit les
# 25 outils de lecture. Or le vrai profil de risque n'est pas binaire.
# Renommer un tag ou recategoriser une transaction se defait en deux clics
# dans Monarch. Supprimer une transaction, non. Et une regle automatique
# s'applique retroactivement : une regle trop large recategorise l'historique
# entier d'un coup (probleme ouvert sur le depot amont).
#
# On retire donc les outils un par un apres l'enregistrement, via
# ``remove_tool``. Un outil retire ne figure plus dans ``tools/list`` : le
# modele ne peut pas l'appeler, meme s'il est convaincu par un libelle de
# transaction malveillant. C'est la meme garantie que le mode lecture seule,
# a la granularite pres.

DEFAULT_BLOCKED_TOOLS = (
    # Destructif et non reversible depuis la conversation.
    "delete_transaction",
    # Regles automatiques : effet retroactif et en masse.
    "create_transaction_rule",
    "update_transaction_rule",
    "delete_transaction_rule",
    # Mutation de session. Sur un serveur distant partage entre tes appareils,
    # un logout declenche par megarde couperait l'acces partout a la fois, et
    # ces outils passent par l'elicitation MCP, qui n'a de toute facon pas de
    # sens sans terminal interactif.
    "monarch_login",
    "monarch_login_with_token",
    "monarch_logout",
    "setup_authentication",
)


def _blocked_tools() -> list[str]:
    """Liste effective des outils a retirer.

    ``MONARCH_MCP_BLOCKED_TOOLS`` remplace entierement la liste par defaut
    (vide = aucun retrait, donc les 49 outils). Le remplacement est
    volontairement total plutot qu'additif : une liste de securite qu'on ne
    lit qu'a moitie est pire qu'une liste explicite.
    """
    raw = os.environ.get("MONARCH_MCP_BLOCKED_TOOLS")
    if raw is None:
        return list(DEFAULT_BLOCKED_TOOLS)
    return [name.strip() for name in raw.split(",") if name.strip()]


def apply_tool_blocklist(server: Any) -> list[str]:
    removed: list[str] = []
    for name in _blocked_tools():
        try:
            server.remove_tool(name)
        except Exception as exc:  # outil deja absent (ex. mode lecture seule)
            logger.debug("Outil %s non retire : %s", name, exc)
            continue
        removed.append(name)
    if removed:
        logger.warning("Outils retires (%d) : %s", len(removed), ", ".join(removed))
    return removed


BLOCKED_TOOLS = apply_tool_blocklist(mcp)


class AuthGateway:
    """Middleware ASGI : laisse passer /healthz, exige le secret ailleurs.

    Ecrit en ASGI brut plutot qu'en ``BaseHTTPMiddleware`` parce que le
    transport streamable HTTP diffuse des reponses longues ; l'enveloppe
    requete/reponse de Starlette met ce flux en tampon et casse le streaming.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        if path in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        # a) Secret dans l'URL : /s/<secret>/mcp  ->  /mcp
        if path.startswith(SECRET_PREFIX):
            remainder = path[len(SECRET_PREFIX) :] or MCP_PATH
            if not remainder.startswith("/"):
                remainder = "/" + remainder
            scope = dict(scope)
            scope["path"] = remainder
            scope["raw_path"] = remainder.encode("utf-8")
            await self.app(scope, receive, send)
            return

        # b) En-tete Authorization: Bearer <secret>
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        raw_auth = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, presented = raw_auth.partition(" ")
        if scheme.lower() == "bearer" and secrets.compare_digest(
            presented.strip(), MCP_AUTH_TOKEN
        ):
            await self.app(scope, receive, send)
            return

        await Response(
            content=json.dumps(
                {
                    "error": "unauthorized",
                    "detail": (
                        "Fournis Authorization: Bearer <token>, ou utilise "
                        "l'URL a segment secret /s/<token>/mcp."
                    ),
                }
            ),
            status_code=401,
            media_type="application/json",
            headers={"WWW-Authenticate": 'Bearer realm="monarch-mcp"'},
        )(scope, receive, send)


async def healthz(_request: Any) -> JSONResponse:
    """Sonde de sante — volontairement sans donnee financiere.

    Render (et tout autre hebergeur) l'appelle sans en-tete d'authentification,
    donc elle ne doit rien reveler d'autre que l'etat du processus.
    """
    return JSONResponse(
        {
            "status": "ok",
            "server": "monarch-mcp-remote",
            "auth_mode": AUTH_MODE,
            "read_only": is_read_only(),
            "blocked_tools": BLOCKED_TOOLS,
            "mcp_path": MCP_PATH,
        }
    )


# --------------------------------------------------------------------------
# 3. Assemblage de l'application
# --------------------------------------------------------------------------

# ``stateless_http=True`` : chaque requete est autonome. Sur un hebergeur qui
# peut redemarrer ou repartir le trafic entre instances, une session collante
# cote serveur se perdrait en cours de conversation.
# ``allowed_hosts=["*"]`` : la protection anti-DNS-rebinding vise les clients
# navigateur en localhost. Ici l'hebergeur termine le TLS et reecrit l'en-tete
# Host ; c'est le secret qui protege l'endpoint, pas le nom d'hote.
mcp_app = mcp.streamable_http_app(
    streamable_http_path=MCP_PATH,
    stateless_http=True,
    json_response=False,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
        allowed_hosts=["*"],
        allowed_origins=["*"],
    ),
)

mcp_app.routes.append(Route("/healthz", healthz, methods=["GET"]))

app = AuthGateway(mcp_app)


def main() -> None:
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    logger.info(
        "Demarrage : port=%s read_only=%s auth_mode=%s",
        port,
        is_read_only(),
        AUTH_MODE,
    )
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
