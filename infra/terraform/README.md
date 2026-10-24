# SecuriGlass Factory OS — Infrastructure as Code (Terraform / Docker)

Déploiement local de la pile **PostgreSQL 16 + pgAudit** et **backend API
distroless** avec segmentation réseau de type Purdue (OT / IT / DMZ).

> Périmètre : PoC mono-machine (Docker Desktop). Pour un socle de production,
> voir la section [Limites](#limites-assumées).

---

## 1. Prérequis

| Outil | Version minimale | Vérification |
| :--- | :--- | :--- |
| Terraform | 1.6 | `terraform version` |
| Docker Engine / Desktop | 24 | `docker version` |
| Images du projet | — | voir §2 |

Le provider utilise le socket local (`unix:///var/run/docker.sock`). Sur macOS,
Docker Desktop doit être démarré. Pour un hôte distant, surcharger
`docker_host` (ex. `tcp://docker.example.local:2376`) **avec TLS mutuel**.

---

## 2. Construire les images

```bash
# PostgreSQL 16 + pgAudit (image existante du projet)
docker build -t docker-securiglass-db:latest infra/docker/postgres

# Backend distroless non-root (contexte = racine du dépôt)
docker build -f security/docker/backend.Dockerfile \
  -t securiglass/backend-api:1.0.0 .

# Vérifier le durcissement de l'image
docker image inspect securiglass/backend-api:1.0.0 --format '{{.Config.User}}'
# -> 65532:65532
```

---

## 3. Déployer

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # puis remplacer les CHANGE_ME
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Secrets : `postgres_password`, `backend_secret_key`, `tde_encryption_key` sont
`required` et `sensitive`. Ils peuvent aussi être fournis par
`TF_VAR_postgres_password=...` ou un coffre (Vault/SOPS), sans jamais être
écrits dans le dépôt.

### Vérifier le déploiement

```bash
terraform output backend_url
curl -fsS "$(terraform output -raw backend_url)/health"
docker inspect --format '{{.State.Health.Status}}' securiglass-backend-api
docker inspect --format '{{.State.Health.Status}}' securiglass-postgres
```

### Accéder à PostgreSQL

Aucun port n'est publié sur l'hôte (surface d'attaque nulle côté LAN). Passer par
le conteneur :

```bash
docker exec -it securiglass-postgres \
  psql -U securiglass_admin -d securiglass_db -c 'SELECT version();'
```

### Détruire

```bash
terraform destroy
# Les volumes securiglass-pgdata / securiglass-pgbackup sont conserves par
# defaut ; les supprimer explicitement :
docker volume rm securiglass-pgdata securiglass-pgbackup
```

---

## 4. Segmentation réseau

| Réseau | CIDR | Rôle | `internal` | Conteneurs |
| :--- | :--- | :--- | :--- | :--- |
| `securiglass-net-ot` | `10.10.30.0/24` | OT (Purdue 1-3) | oui | réservé à l'edge gateway OT |
| `securiglass-net-it` | `10.20.0.0/24` | IT (Purdue 4) | oui | PostgreSQL `10.20.0.10`, backend `10.20.0.20` |
| `securiglass-net-dmz` | `10.30.0.0/24` | DMZ (Purdue 3.5) | non | backend `10.30.0.10` |

- Le backend est le **seul** conteneur à cheval IT/DMZ : il expose l'API en DMZ
  et joint PostgreSQL sur IT.
- `internal = true` supprime la route sortante : aucun exfiltrage direct depuis
  OT/IT.
- L'API n'est publiée que sur `127.0.0.1:8000` par défaut (modifiable via
  `backend_bind_address`, à ne faire qu'avec un reverse proxy TLS devant).

### Flux autorisés (implicites)

```
Hôte (loopback) --8000/tcp--> backend (DMZ)
backend (IT)    --5432/tcp--> postgres (IT)
```

Aucun autre flux n'est possible entre les réseaux (pas de routage Docker entre
bridges). L'edge gateway OT, lorsqu'il sera déployé, devra être rattaché à
`net-ot` **et** `net-dmz` avec une politique de filtrage dédiée (la diode
logicielle de l'étape 2).

---

## 5. Durcissement appliqué

| Contrôle | PostgreSQL | Backend |
| :--- | :--- | :--- |
| Utilisateur | `postgres` (non-root) | `65532:65532` (distroless nonroot) |
| Racine en lecture seule | oui (volumes + tmpfs) | oui (tmpfs `/tmp`) |
| `cap_drop` | `ALL` + caps minimales Docker | `ALL` |
| `no-new-privileges` | oui | oui |
| Healthcheck | `pg_isready` | `GET /health` sans shell (Python) |
| Port publié | aucun | loopback uniquement |
| Secrets | variables sensibles | variables sensibles |
| Schémas métier | `database/schemas/*.sql` montés en RO | — |

---

## 6. Variables

Toutes les variables sont documentées dans [`variables.tf`](variables.tf).
Valeurs par défaut notables :

| Variable | Défaut | Notes |
| :--- | :--- | :--- |
| `postgres_image` | `docker-securiglass-db:latest` | tag du compose ; préférer un tag immuable |
| `backend_image` | `securiglass/backend-api:1.0.0` | image construite §2 |
| `backend_port` | `8000` | bind sur `backend_bind_address` |
| `net_*_subnet` | `10.10.30.0/24`, `10.20.0.0/24`, `10.30.0.0/24` | CIDR validés |
| `postgres_password` | — | **obligatoire**, ≥ 20 caractères |
| `backend_secret_key` | — | **obligatoire**, ≥ 64 caractères |
| `tde_encryption_key` | — | **obligatoire**, 64 hex (AES-256) |

---

## 7. Limites assumées

1. **État local non chiffré.** `terraform.tfstate` contient les secrets
   (variables sensibles comprises). Pour la production : backend distant
   chiffré (S3 + KMS + verrou DynamoDB) et état jamais versionné.
2. **Pas de terminaison TLS.** L'API écoute en HTTP sur loopback. Un reverse
   proxy TLS (nginx/Traefik) avec certificats doit être ajouté devant.
3. **Pas de frontend.** Seuls PostgreSQL et le backend sont déployés ici ; le
   frontend (`security/docker/frontend.Dockerfile`) est destiné à un reverse
   proxy / un autre compose.
4. **Pas de sauvegarde automatique.** Le volume `securiglass-pgbackup` est
   fourni comme cible ; aucune planification `pg_dump`/WAL n'est configurée.
   À couvrir par un job CronJob/hôte dédié (PRA).
5. **Pas de rotation de secrets.** Les secrets sont injectés à la création ;
   une rotation nécessite `terraform apply` (redémarrage des conteneurs).
6. **Provider Docker local.** Pas de haute disponibilité, pas de multi-nœuds,
   pas de politique réseau L3/L4 fine (le filtrage inter-réseaux est assuré par
   l'absence de routage Docker, pas par un pare-feu).
7. **Image PostgreSQL basée sur une image tierce.** L'image
   `docker-securiglass-db:latest` provient de `infra/docker/postgres` (périmètre
   validé en amont) ; sa reconstruction est requise avant `apply`.
8. **Pas de scan d'image ici.** Les scans Trivy sont exécutés en CI
   (`.github/workflows/ci.yml`), pas par Terraform.
