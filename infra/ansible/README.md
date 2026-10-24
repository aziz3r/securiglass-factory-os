# SecuriGlass Factory OS — Ansible : durcissement CIS Linux

Rôle `cis_linux` + playbook de durcissement des hôtes Linux (Debian/Ubuntu,
RHEL/Rocky/Alma) conformément aux **CIS Benchmarks**, à **IEC 62443-3-3** et aux
recommandations ANSSI.

---

## 1. Contenu

| Élément | Rôle |
| :--- | :--- |
| `playbook-hardening.yml` | Point d'entrée, pré-vol (OS/conteneur) et post-vol (`sshd -T`) |
| `roles/cis_linux/tasks/ssh.yml` | SSH durci (clés uniquement, root interdit, crypto forte) |
| `roles/cis_linux/tasks/sysctl.yml` | Noyau/réseau (rp_filter, redirects, syncookies, kptr_restrict…) |
| `roles/cis_linux/tasks/auditd.yml` | Règles d'audit (identité, SSH, sudoers, modules, escalade) |
| `roles/cis_linux/tasks/journald.yml` | Journal persistant, compressé et scellé (FSS) |
| `roles/cis_linux/tasks/permissions.yml` | `/etc/shadow`, cron, `login.defs` |
| `roles/cis_linux/tasks/umask.yml` | `umask 027` (shell + services systemd) |
| `roles/cis_linux/tasks/services.yml` | Désactivation des services/sockets inutiles |
| `roles/cis_linux/tasks/banner.yml` | Bannières légales `/etc/issue*`, `/etc/motd` |
| `inventory.example.ini` | Inventaire d'exemple (hôte TEST-NET, non routable) |
| `ansible.cfg` | Roles path, vault (opt-in), escalade, pipelining |

---

## 2. Utilisation

```bash
cd infra/ansible

# 1. Inventaire réel (non versionné)
cp inventory.example.ini inventory.ini
$EDITOR inventory.ini

# 2. Vérification de syntaxe (sans connexion)
ansible-playbook -i inventory.example.ini playbook-hardening.yml --syntax-check

# 3. Simulation complète (aucune modification)
ansible-playbook -i inventory.ini playbook-hardening.yml --check --diff

# 4. Application
ansible-playbook -i inventory.ini playbook-hardening.yml --diff

# 5. Application ciblée
ansible-playbook -i inventory.ini playbook-hardening.yml --tags ssh
```

Tags disponibles : `cis_linux`, `packages`, `ssh`, `sysctl`, `auditd`,
`journald`, `permissions`, `umask`, `services`, `banner`.

### Secrets / Vault

Aucun secret n'est versionné. La configuration Vault est **opt-in** : une
identité déclarée mais absente ferait échouer toutes les invocations (y compris
`--syntax-check`). Utiliser l'une des deux formes :

```bash
ansible-vault create group_vars/all/vault.yml \
  --vault-id default@~/.ansible/securiglass-vault-id

ANSIBLE_VAULT_IDENTITY_LIST=default@~/.ansible/securiglass-vault-id \
  ansible-playbook -i inventory.ini playbook-hardening.yml --ask-vault-pass
```

`no_log` n'est pas une option globale d'`ansible.cfg` (c'est un keyword de tâche
ou de play) : le playbook expose `cis_no_log: true`, appliqué aux tâches
manipulant des extraits sensibles.

---

## 3. Avertissements de sécurité

- **Verrouillage SSH** : `PermitRootLogin no` et
  `PasswordAuthentication no` sont appliqués. Vérifier qu'une clé autorisée est
  présente **avant** de fermer la session courante. Le template est validé par
  `sshd -t` avant écriture, et une sauvegarde horodatée est conservée.
- **Drop-in SSH** : `/etc/ssh/sshd_config.d/*.conf` n'est volontairement pas
  inclus, afin qu'aucune surcharge ne réactive un réglage faible. Si votre
  distribution utilise ces drop-in (cloud-init), adaptez le template.
- **auditd** : inopérant dans un conteneur non privilégié ; le playbook avertit
  si `ansible_virtualization_type` vaut `docker`/`container`. Les règles sont
  chargées par `augenrules --load` puis `auditd` redémarré. L'immutabilité
  (`-e 2`) est fournie commentée : elle exige un redémarrage pour être levée.
- **services.yml** : `failed_when: false` sur la désactivation des services
  optionnels ; un service absent/masqué ne bloque pas le playbook. Contrôler le
  récapitulatif `changed/failed`.
- **network** : le playbook ne gère **pas** le pare-feu (nftables/iptables) ni
  SELinux/AppArmor ; à traiter dans un rôle dédié.

---

## 4. Vérifications

```bash
ansible-playbook -i inventory.example.ini playbook-hardening.yml --syntax-check
ansible-config dump --only-changed
ansible-inventory -i inventory.example.ini --graph
```

En CI/QA sans hôte cible, valider au minimum :

```bash
python - <<'PY'
import pathlib, yaml
for p in pathlib.Path("infra/ansible").rglob("*.yml"):
    if "templates" not in p.parts:
        yaml.safe_load(p.read_text())
print("YAML Ansible OK")
PY
```

---

## 5. Limites

1. Cible **hôtes réels** ou VM ; pas de support conteneur pour auditd/journald.
2. Aucun test `molecule` fourni (pas de dépendance lourde ajoutée au PoC).
3. Pas de gestion du pare-feu, de SELinux/AppArmor, ni de politique de mots de
   passe PAM (`pwquality`) — volontairement hors périmètre de ce livrable.
4. Les versions de paquets ne sont pas épinglées : le durcissement est
   idempotent, mais pas reproductible au bit près (pas de miroir APT interne).
5. Les services listés dans `cis_disabled_services` sont désactivés **s'ils
   existent** ; vérifier la liste pour votre base d'installation (ne pas
   désactiver un service métier).
