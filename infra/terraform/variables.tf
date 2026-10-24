# =============================================================================
# SecuriGlass Factory OS - Variables Terraform
# =============================================================================
# Aucun secret n'a de valeur par defaut : les variables sensibles doivent etre
# fournies via terraform.tfvars (non versionne), des variables d'environnement
# TF_VAR_* ou un coffre (Vault / SOPS). Voir terraform.tfvars.example.
# =============================================================================

# -----------------------------------------------------------------------------
# Connexion au moteur Docker
# -----------------------------------------------------------------------------
variable "docker_host" {
  description = "Endpoint du demon Docker (socket local ou TCP/TLS)."
  type        = string
  default     = "unix:///var/run/docker.sock"

  validation {
    condition     = can(regex("^(unix://|tcp://|npipe://|ssh://)", var.docker_host))
    error_message = "docker_host doit commencer par unix://, tcp://, npipe:// ou ssh://."
  }
}

variable "project_name" {
  description = "Prefixe des ressources Docker (reseaux, volumes, conteneurs)."
  type        = string
  default     = "securiglass"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.project_name))
    error_message = "project_name doit etre en minuscules (lettres, chiffres, tirets), 2 a 31 caracteres."
  }
}

variable "environment" {
  description = "Environnement de deploiement (injecte dans le backend)."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["development", "test", "staging", "production"], var.environment)
    error_message = "environment doit valoir development, test, staging ou production."
  }
}

# -----------------------------------------------------------------------------
# Images (construites depuis le depot, jamais tirees depuis un registre public)
# -----------------------------------------------------------------------------
variable "postgres_image" {
  description = "Image PostgreSQL 16 + pgAudit construite depuis infra/docker/postgres."
  type        = string
  default     = "docker-securiglass-db:latest"
}

variable "backend_image" {
  description = "Image backend distroless construite depuis security/docker/backend.Dockerfile."
  type        = string
  default     = "securiglass/backend-api:1.0.0"
}

# -----------------------------------------------------------------------------
# Segmentation reseau (CIDR / adresses statiques)
# -----------------------------------------------------------------------------
variable "net_ot_subnet" {
  description = "Sous-reseau OT (Purdue 1-3)."
  type        = string
  default     = "10.10.30.0/24"
  validation {
    condition     = can(cidrhost(var.net_ot_subnet, 1))
    error_message = "net_ot_subnet doit etre un CIDR IPv4 valide."
  }
}

variable "net_it_subnet" {
  description = "Sous-reseau IT (Purdue 4)."
  type        = string
  default     = "10.20.0.0/24"
  validation {
    condition     = can(cidrhost(var.net_it_subnet, 1))
    error_message = "net_it_subnet doit etre un CIDR IPv4 valide."
  }
}

variable "net_dmz_subnet" {
  description = "Sous-reseau DMZ (exposition maitrisee de l'API)."
  type        = string
  default     = "10.30.0.0/24"
  validation {
    condition     = can(cidrhost(var.net_dmz_subnet, 1))
    error_message = "net_dmz_subnet doit etre un CIDR IPv4 valide."
  }
}

variable "postgres_ip" {
  description = "Adresse statique du conteneur PostgreSQL sur net-it."
  type        = string
  default     = "10.20.0.10"
}

variable "backend_dmz_ip" {
  description = "Adresse statique du backend sur net-dmz."
  type        = string
  default     = "10.30.0.10"
}

variable "backend_it_ip" {
  description = "Adresse statique du backend sur net-it (acces a PostgreSQL)."
  type        = string
  default     = "10.20.0.20"
}

variable "ot_control_room_cidr" {
  description = "CIDR de la salle de controle OT (Purdue 2), transmis au moteur ABAC."
  type        = string
  default     = "10.10.20.0/24"
  validation {
    condition     = can(cidrhost(var.ot_control_room_cidr, 1))
    error_message = "ot_control_room_cidr doit etre un CIDR IPv4 valide."
  }
}

variable "ot_gateway_cidr" {
  description = "CIDR du reseau OT (Purdue 3), transmis au moteur ABAC."
  type        = string
  default     = "10.10.30.0/24"
  validation {
    condition     = can(cidrhost(var.ot_gateway_cidr, 1))
    error_message = "ot_gateway_cidr doit etre un CIDR IPv4 valide."
  }
}

# -----------------------------------------------------------------------------
# Exposition du backend
# -----------------------------------------------------------------------------
variable "backend_port" {
  description = "Port hote publie pour l'API backend (bind sur 127.0.0.1 par defaut)."
  type        = number
  default     = 8000

  validation {
    condition     = var.backend_port >= 1024 && var.backend_port <= 65535
    error_message = "backend_port doit etre compris entre 1024 et 65535."
  }
}

variable "backend_bind_address" {
  description = "Adresse d'ecoute du port publie (127.0.0.1 = poste local uniquement)."
  type        = string
  default     = "127.0.0.1"
  validation {
    condition     = can(cidrhost("${var.backend_bind_address}/32", 0))
    error_message = "backend_bind_address doit etre une adresse IPv4."
  }
}

# -----------------------------------------------------------------------------
# PostgreSQL (secrets obligatoires, sans valeur par defaut)
# -----------------------------------------------------------------------------
variable "postgres_db" {
  description = "Nom de la base applicative."
  type        = string
  default     = "securiglass_db"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{2,62}$", var.postgres_db))
    error_message = "postgres_db doit etre un identifiant PostgreSQL valide."
  }
}

variable "postgres_user" {
  description = "Role administrateur PostgreSQL."
  type        = string
  default     = "securiglass_admin"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{2,62}$", var.postgres_user))
    error_message = "postgres_user doit etre un identifiant PostgreSQL valide."
  }
}

variable "postgres_password" {
  description = "Mot de passe PostgreSQL (obligatoire, jamais versionne)."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.postgres_password) >= 20
    error_message = "postgres_password doit contenir au moins 20 caracteres."
  }
}

# -----------------------------------------------------------------------------
# Secrets applicatifs du backend (obligatoires, jamais versionnes)
# -----------------------------------------------------------------------------
variable "backend_secret_key" {
  description = "Cle de signature JWT (>= 64 caracteres recommandes)."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.backend_secret_key) >= 64
    error_message = "backend_secret_key doit contenir au moins 64 caracteres."
  }
}

variable "tde_encryption_key" {
  description = "Cle TDE AES-256-GCM : 64 caracteres hexadecimaux (32 octets)."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.tde_encryption_key))
    error_message = "tde_encryption_key doit etre 64 caracteres hexadecimaux."
  }
}

variable "backend_log_level" {
  description = "Niveau de log du backend."
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], var.backend_log_level)
    error_message = "backend_log_level doit etre DEBUG, INFO, WARNING, ERROR ou CRITICAL."
  }
}

variable "db_pool_min" {
  description = "Taille minimale du pool asyncpg."
  type        = number
  default     = 5
  validation {
    condition     = var.db_pool_min >= 1 && var.db_pool_min <= 50
    error_message = "db_pool_min doit etre compris entre 1 et 50."
  }
}

variable "db_pool_max" {
  description = "Taille maximale du pool asyncpg."
  type        = number
  default     = 20
  validation {
    condition     = var.db_pool_max >= 2 && var.db_pool_max <= 100
    error_message = "db_pool_max doit etre compris entre 2 et 100."
  }
}
