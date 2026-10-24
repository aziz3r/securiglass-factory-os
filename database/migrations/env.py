"""Environnement Alembic - SecuriGlass Factory OS.

Le DSN provient exclusivement de l'environnement (aucun secret versionné).
Le schéma est créé par les scripts DDL `database/schemas/*.sql` (source de
vérité métier) exécutés depuis la révision 0001.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_DEFAULT_DSN = "postgresql://securiglass_admin:SecuriGlass_Admin_2026!MasterKey@localhost:5432/securiglass_db"


def _database_url() -> str:
    url = (
        os.environ.get("SECURIGLASS_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or _DEFAULT_DSN
    )
    # SQLAlchemy 2.x exige le nom du driver explicite pour psycopg2.
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    return url


config.set_main_option("sqlalchemy.url", _database_url().replace("%", "%%"))

target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, compare_type=True
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
