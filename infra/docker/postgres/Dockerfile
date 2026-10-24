# SecuriGlass - PostgreSQL 16 durci (pgAudit / IEC 62443 / CIS)
#
# Base Debian et non Alpine : `pgaudit` n'est pas fourni par les dépôts Alpine
# (`postgresql16-contrib` ne le contient pas), ce qui provoquait au démarrage
#   FATAL: could not access file "pgaudit"
# et une boucle de redémarrage (aucun schéma initialisé). `postgres:16-bookworm`
# embarque le dépôt PGDG officiel, qui distribue `postgresql-16-pgaudit`.
FROM postgres:16-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-16-pgaudit \
    && rm -rf /var/lib/apt/lists/*

# Configuration persistante injectée dans le modèle utilisé par initdb.
# `pg_config --sharedir` = /usr/share/postgresql/16 sur l'image Debian : ne pas
# coder le chemin en dur, et pas de heredoc (builder classique).
RUN SHAREDIR="$(pg_config --sharedir)" \
    && printf '%s\n' \
        '' \
        '# ---------------------------------------------------------------------------' \
        '# SecuriGlass - Audit pgAudit (charge au demarrage du serveur)' \
        '# ---------------------------------------------------------------------------' \
        "shared_preload_libraries = 'pgaudit'" \
        "pgaudit.log = 'role, ddl, write, function'" \
        'pgaudit.log_parameter = on' \
        'pgaudit.log_catalog = off' \
        "pgaudit.log_level = 'log'" \
        >> "$SHAREDIR/postgresql.conf.sample" \
    && grep -q "shared_preload_libraries = 'pgaudit'" "$SHAREDIR/postgresql.conf.sample"

# Le serveur ne tourne jamais en root.
USER postgres
