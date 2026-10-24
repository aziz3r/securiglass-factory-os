# =============================================================================
# SecuriGlass Factory OS - Ressources Docker (segmentation Purdue / IEC 62443)
# =============================================================================
# Principes appliques :
#   - reseaux separes OT / IT / DMZ, adressage statique ;
#   - aucun port PostgreSQL publie sur l'hote (accessible uniquement via net-it) ;
#   - backend : racine en lecture seule, tmpfs pour /tmp, cap_drop ALL,
#     no-new-privileges, utilisateur 65532:65532 (distroless nonroot) ;
#   - PostgreSQL : racine en lecture seule, volume pgdata, caps minimales ;
#   - healthchecks natifs Docker pour les deux conteneurs.
# =============================================================================

locals {
  prefix = var.project_name

  labels = {
    "com.securiglass.project"     = "factory-os"
    "com.securiglass.managed-by"  = "terraform"
    "com.securiglass.environment" = var.environment
  }

  postgres_container_name = "${local.prefix}-postgres"
  backend_container_name  = "${local.prefix}-backend-api"

  # Les composants du DSN sont encodes (mot de passe pouvant contenir @ : / #).
  database_url = format(
    "postgresql://%s:%s@%s:5432/%s",
    urlencode(var.postgres_user),
    urlencode(var.postgres_password),
    local.postgres_container_name,
    var.postgres_db,
  )

  backend_healthcheck_cmd = "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).getcode() == 200 else 1)"

  # Scripts DDL de reference montes en lecture seule dans initdb (premier demarrage).
  schema_files = fileset("${path.module}/../../database/schemas", "*.sql")
}

# -----------------------------------------------------------------------------
# Reseaux segmentes
# -----------------------------------------------------------------------------
resource "docker_network" "net_ot" {
  name     = "${local.prefix}-net-ot"
  driver   = "bridge"
  internal = true

  ipam_config {
    subnet = var.net_ot_subnet
  }

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

resource "docker_network" "net_it" {
  name     = "${local.prefix}-net-it"
  driver   = "bridge"
  internal = true

  ipam_config {
    subnet = var.net_it_subnet
  }

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

resource "docker_network" "net_dmz" {
  name     = "${local.prefix}-net-dmz"
  driver   = "bridge"
  internal = false

  ipam_config {
    subnet = var.net_dmz_subnet
  }

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# -----------------------------------------------------------------------------
# Volumes persistants
# -----------------------------------------------------------------------------
resource "docker_volume" "pgdata" {
  name   = "${local.prefix}-pgdata"
  driver = "local"

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# Cible des sauvegardes chiffrees (pg_dump / pg_basebackup). Aucune sauvegarde
# automatique n'est configuree ici : voir README (limite explicite).
resource "docker_volume" "pgbackup" {
  name   = "${local.prefix}-pgbackup"
  driver = "local"

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# -----------------------------------------------------------------------------
# PostgreSQL 16 + pgAudit (IT)
# -----------------------------------------------------------------------------
resource "docker_container" "postgres" {
  name      = local.postgres_container_name
  image     = var.postgres_image
  restart   = "unless-stopped"
  must_run  = true
  read_only = true
  user      = "postgres"

  # Moindre privilege : aucune capability, puis uniquement celles requises par
  # l'entrypoint officiel (chown des volumes + bascule d'utilisateur).
  capabilities {
    drop = ["ALL"]
    add  = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]
  }

  security_opts = ["no-new-privileges:true"]

  env = [
    "POSTGRES_DB=${var.postgres_db}",
    "POSTGRES_USER=${var.postgres_user}",
    "POSTGRES_PASSWORD=${var.postgres_password}",
    "PGDATA=/var/lib/postgresql/data/pgdata",
    "POSTGRES_INITDB_ARGS=--data-checksums --auth-host=scram-sha-256 --auth-local=trust",
  ]

  networks_advanced {
    name         = docker_network.net_it.name
    ipv4_address = var.postgres_ip
  }

  # Volume de donnees (seul point inscriptible persistant).
  mounts {
    type   = "volume"
    source = docker_volume.pgdata.name
    target = "/var/lib/postgresql/data"
  }

  mounts {
    type   = "volume"
    source = docker_volume.pgbackup.name
    target = "/var/lib/postgresql/backups"
  }

  # Repertoires d'execution requis par PostgreSQL sur une racine read-only.
  mounts {
    type   = "tmpfs"
    target = "/tmp"
    tmpfs_options {
      size_bytes = 67108864
      mode       = 1777
    }
  }

  mounts {
    type   = "tmpfs"
    target = "/var/run/postgresql"
    tmpfs_options {
      size_bytes = 16777216
      mode       = 1777
    }
  }

  # Initialisation des schemas metier au premier demarrage (lecture seule).
  dynamic "mounts" {
    for_each = local.schema_files
    content {
      type      = "bind"
      source    = abspath("${path.module}/../../database/schemas/${mounts.value}")
      target    = "/docker-entrypoint-initdb.d/${mounts.value}"
      read_only = true
    }
  }

  healthcheck {
    test         = ["CMD-SHELL", "pg_isready -U ${var.postgres_user} -d ${var.postgres_db}"]
    interval     = "15s"
    timeout      = "5s"
    retries      = 5
    start_period = "20s"
  }

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# -----------------------------------------------------------------------------
# Backend API distroless (DMZ + IT pour joindre PostgreSQL)
# -----------------------------------------------------------------------------
resource "docker_container" "backend" {
  name      = local.backend_container_name
  image     = var.backend_image
  restart   = "unless-stopped"
  must_run  = true
  read_only = true
  user      = "65532:65532"

  capabilities {
    drop = ["ALL"]
  }

  security_opts = ["no-new-privileges:true"]

  env = [
    "ENVIRONMENT=${var.environment}",
    "LOG_LEVEL=${var.backend_log_level}",
    "DATABASE_URL=${local.database_url}",
    "DB_MIN_CONNECTIONS=${var.db_pool_min}",
    "DB_MAX_CONNECTIONS=${var.db_pool_max}",
    "SECRET_KEY=${var.backend_secret_key}",
    "TDE_ENCRYPTION_KEY=${var.tde_encryption_key}",
    "JWT_ALGORITHM=HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES=30",
    "OT_CONTROL_ROOM_CIDR=${var.ot_control_room_cidr}",
    "OT_GATEWAY_CIDR=${var.ot_gateway_cidr}",
  ]

  networks_advanced {
    name         = docker_network.net_dmz.name
    ipv4_address = var.backend_dmz_ip
  }

  networks_advanced {
    name         = docker_network.net_it.name
    ipv4_address = var.backend_it_ip
  }

  # Seul point inscriptible : /tmp (uvicorn / multipart), en tmpfs.
  mounts {
    type   = "tmpfs"
    target = "/tmp"
    tmpfs_options {
      size_bytes = 67108864
      mode       = 1777
    }
  }

  # Exposition maitrisee : loopback uniquement par defaut.
  ports {
    internal = 8000
    external = var.backend_port
    ip       = var.backend_bind_address
    protocol = "tcp"
  }

  healthcheck {
    test         = ["CMD", "/opt/venv/bin/python", "-c", local.backend_healthcheck_cmd]
    interval     = "30s"
    timeout      = "5s"
    retries      = 3
    start_period = "15s"
  }

  depends_on = [docker_container.postgres]

  dynamic "labels" {
    for_each = local.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}
