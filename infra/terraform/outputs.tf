# =============================================================================
# SecuriGlass Factory OS - Sorties Terraform
# =============================================================================
# Aucune sortie ne contient de secret (mot de passe, cle JWT ou cle TDE).
# =============================================================================

output "networks" {
  description = "Reseaux Docker segmentes (nom -> identifiant)."
  value = {
    ot  = docker_network.net_ot.name
    it  = docker_network.net_it.name
    dmz = docker_network.net_dmz.name
  }
}

output "network_subnets" {
  description = "Plan d'adressage applique (CIDR par zone)."
  value = {
    ot  = var.net_ot_subnet
    it  = var.net_it_subnet
    dmz = var.net_dmz_subnet
  }
}

output "volumes" {
  description = "Volumes persistants PostgreSQL."
  value = {
    pgdata   = docker_volume.pgdata.name
    pgbackup = docker_volume.pgbackup.name
  }
}

output "postgres_container" {
  description = "Conteneur PostgreSQL (nom, identifiant, adresse interne)."
  value = {
    name           = docker_container.postgres.name
    id             = docker_container.postgres.id
    internal_host  = "${docker_container.postgres.name}:5432"
    ip             = var.postgres_ip
    published_port = null
  }
}

output "backend_container" {
  description = "Conteneur backend (nom, identifiant, adresses internes)."
  value = {
    name   = docker_container.backend.name
    id     = docker_container.backend.id
    ip_dmz = var.backend_dmz_ip
    ip_it  = var.backend_it_ip
  }
}

output "backend_url" {
  description = "URL locale de l'API (bind loopback par defaut)."
  value       = "http://${var.backend_bind_address}:${var.backend_port}"
}

output "backend_healthcheck" {
  description = "Commande de verification manuelle du healthcheck backend."
  value       = "docker inspect --format '{{.State.Health.Status}}' ${docker_container.backend.name}"
}

output "segmentation_summary" {
  description = "Vue synthetique de la segmentation appliquee."
  value = {
    ot  = "${docker_network.net_ot.name} (${var.net_ot_subnet}) : interne, reserve a l'edge gateway OT"
    it  = "${docker_network.net_it.name} (${var.net_it_subnet}) : interne, PostgreSQL + interface IT du backend"
    dmz = "${docker_network.net_dmz.name} (${var.net_dmz_subnet}) : backend, seul reseau avec passerelle"
  }
}
