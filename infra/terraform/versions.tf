# =============================================================================
# SecuriGlass Factory OS - Infrastructure as Code (Docker provider)
# =============================================================================
# Segmentation reseau Purdue :
#   net-ot  10.10.30.0/24  Niveaux 1-3 OT (reserve a l'edge gateway / automate)
#   net-it  10.20.0.0/24   Niveau 4 IT (PostgreSQL, services de donnees)
#   net-dmz 10.30.0.0/24   Zone demilitarisee (API backend, exposition maitrisee)
#
# Les reseaux net-ot et net-it sont "internal" (pas de route sortante) ; seul
# net-dmz dispose d'une passerelle, et le backend n'y publie qu'une API locale.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.6"
    }
  }

  # Etat local par defaut (PoC mono-machine).
  # En production : backend distant chiffre + verrouillage, par exemple :
  # backend "s3" {
  #   bucket         = "securiglass-tfstate"
  #   key            = "factory-os/terraform.tfstate"
  #   region         = "eu-west-3"
  #   encrypt        = true
  #   kms_key_id     = "alias/securiglass-tfstate"
  #   dynamodb_table = "securiglass-tfstate-lock"
  # }
}

provider "docker" {
  host = var.docker_host
}
