import os

COLORS = ["#46BFBD", "#F7464A", "#FDB45C", "#FEDCBA"]
SECRET = os.environ.get("FISCALIA_SECRET")
DOMAIN = "fiscalia.io"
PARTIES = [
    "UNITE POR LA LIBERTAD",
    "FRENTE FEDERAL NOS",
    "FRENTE DE IZQUIERDA",
    "JUNTOS POR EL CAMBIO",
    "FRENTE DE TODOS",
    "CONSENSO FEDERAL",
]

VOTES_MATRIX = [
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1],
]

CANDIDATES = ["president", "gobernor", "diputado", "senador", "intendente", "general"]
CIRCUIT = "CIRCUITO"
BOXES = [3112, 3113, 3114]
USERS = [
    {
        "circuito": [CIRCUIT],

        "usuarios": {
            "fiscal3112": {
                "boxes": [3112],
                "roles": [],
                "clave": "MV8R3DV8"
            },
            "fiscal3113": {
                "boxes": [3113],
                "roles": [],
                "clave": "6JGB4T3U"
            },
            "fiscal3114": {
                "boxes": [3114],
                "roles": [],
                "clave": "J2U95S4V"
            },
            "fiscal_escuela_16": {
                "boxes": BOXES,
                "roles": ["escuela", "admin"],
                "clave": "6DJ85567"
            },
            "general": {
                "boxes": BOXES,
                "roles": ["general", "admin"],
                "clave": "Y7EB6KCP"
            },
            "candidato": {
                "boxes": BOXES,
                "roles": ["candidato", "admin"],
                "clave": "S46XP6XN"
            },
            "admin": {
                "boxes": BOXES,
                "roles": ["admin"],
                "clave": "admin"
            },
            "demo": {
                "boxes": BOXES,
                "roles": ["admin"],
                "clave": "demo"
            },

        }
    }
]
