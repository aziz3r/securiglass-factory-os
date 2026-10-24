"""Tests de cohérence de la chaîne CI/CD et des livrables DevSecOps.

Ces tests valident statiquement (sans réseau ni daemon Docker) :
- la syntaxe et les invariants de sécurité des workflows GitHub Actions ;
- les Dockerfiles (non-root, aucune image ``:latest``, distroless, healthcheck) ;
- la cohérence ``terraform fmt`` (skip explicite si le binaire est absent) ;
- la structure du playbook/rôle Ansible et la configuration nginx ;
- les règles Semgrep maison et la politique Trivy.

Exécution :
    pytest security/tests -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS_DIR = _REPO_ROOT / ".github" / "workflows"
_DOCKER_DIR = _REPO_ROOT / "security" / "docker"
_TERRAFORM_DIR = _REPO_ROOT / "infra" / "terraform"
_ANSIBLE_DIR = _REPO_ROOT / "infra" / "ansible"
_CIS_ROLE_DIR = _ANSIBLE_DIR / "roles" / "cis_linux"
_SECURITY_DIR = _REPO_ROOT / "security"

_WORKFLOW_FILES = sorted(_WORKFLOWS_DIR.glob("*.y*ml"))
_DOCKERFILES = sorted(_DOCKER_DIR.glob("*.Dockerfile"))


def _load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _workflow_documents() -> list[tuple[Path, dict[str, Any]]]:
    documents: list[tuple[Path, dict[str, Any]]] = []
    for path in _WORKFLOW_FILES:
        document = _load_yaml(path)
        assert isinstance(document, dict), f"{path} ne contient pas un mapping YAML"
        documents.append((path, document))
    return documents


def _on_key(workflow: dict[str, Any]) -> Any:
    """PyYAML (YAML 1.1) convertit la cle ``on`` en booleen True."""
    return workflow.get("on", workflow.get(True))


def _dockerfile_instructions(path: Path) -> list[tuple[int, str]]:
    instructions: list[tuple[int, str]] = []
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instructions.append((number, line))
    return instructions


# =============================================================================
# GitHub Actions
# =============================================================================


def test_workflows_exist_and_parse() -> None:
    """Au moins un workflow doit exister et être un YAML valide."""
    assert _WORKFLOW_FILES, "Aucun workflow dans .github/workflows"
    for path, workflow in _workflow_documents():
        assert "jobs" in workflow, f"{path} ne declare aucun job"
        assert isinstance(workflow["jobs"], dict)
        assert _on_key(workflow) is not None, f"{path} n'a pas de trigger 'on'"


def test_workflow_permissions_are_restrictive() -> None:
    """Les permissions par defaut sont en lecture seule ; seule la signature ecrit."""
    for path, workflow in _workflow_documents():
        permissions = workflow.get("permissions")
        assert isinstance(permissions, dict), f"{path} doit definir permissions"
        assert permissions.get("contents") == "read", f"{path}: contents doit etre read"
        assert "write-all" not in permissions, f"{path}: write-all interdit"

        for job_id, job in workflow["jobs"].items():
            job_permissions = job.get("permissions", {})
            assert isinstance(job_permissions, dict)
            write_scopes = {
                scope for scope, value in job_permissions.items() if value == "write"
            }
            if write_scopes:
                # Une seule exception encadree : signature keyless Cosign (OIDC).
                assert (
                    job_id == "sign"
                ), f"{path}:{job_id} ne doit pas demander d'ecriture"
                assert "id-token" in write_scopes, f"{path}:{job_id} doit utiliser OIDC"
                assert (
                    "packages" in write_scopes
                ), f"{path}:{job_id} doit pousser l'image"


def test_each_job_has_runner_and_safe_action_pins() -> None:
    """Chaque job a un runner ; aucune action n'est epinglee sur une branche mobile."""
    for path, workflow in _workflow_documents():
        for job_id, job in workflow["jobs"].items():
            assert job.get("runs-on"), f"{path}:{job_id} n'a pas de runs-on"
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses is None:
                    continue
                reference = uses.rsplit("@", 1)[-1]
                assert not uses.endswith(
                    ("@main", "@master", "@latest")
                ), f"{path}:{job_id} epingle {uses} sur une reference mobile"
                assert re.fullmatch(
                    r"v?\d+(?:\.\d+){0,2}", reference
                ), f"{path}:{job_id} action non versionnee : {uses}"


def test_workflow_has_concurrency_and_caches() -> None:
    """Concurrency et caches pip/npm presents, sans secret code en dur."""
    for path, workflow in _workflow_documents():
        assert isinstance(
            workflow.get("concurrency"), (dict, str)
        ), f"{path}: concurrency absent"

    ci = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
    text = ci.read_text(encoding="utf-8")
    assert "cache: pip" in text
    assert "cache: npm" in text
    assert "permissions:\n  contents: read" in text


def test_ci_test_job_uses_plain_postgres_and_skips_pgaudit() -> None:
    """Le job de test utilise postgres:16 standard et exclut les tests pgAudit."""
    ci = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
    workflow = _load_yaml(ci)
    test_job = workflow["jobs"]["test"]

    postgres = test_job.get("services", {}).get("postgres", {})
    assert postgres.get("image") == "postgres:16", "La CI ne doit pas requerir pgAudit"
    assert "pgaudit" not in str(postgres).lower()

    pytest_steps = [
        step for step in test_job["steps"] if "pytest" in str(step.get("run", ""))
    ]
    assert pytest_steps, "Aucune etape pytest"
    command = str(pytest_steps[0]["run"])
    assert '-m "not pgaudit"' in command
    assert "--cov-fail-under=85" in command


def test_ci_pipeline_has_required_security_jobs() -> None:
    """Les jobs lint/test/sast/sca/docker/sbom/sign sont tous definis."""
    workflow = _load_yaml(_REPO_ROOT / ".github" / "workflows" / "ci.yml")
    jobs = workflow["jobs"]
    expected = {"lint", "test", "sast", "sca", "docker", "sbom", "sign"}
    assert expected <= set(jobs), f"Jobs manquants : {expected - set(jobs)}"

    docker_job = jobs["docker"]
    trivy_steps = [
        step
        for step in docker_job["steps"]
        if "trivy-action" in str(step.get("uses", ""))
    ]
    assert trivy_steps, "Aucune etape Trivy"
    trivy_args = trivy_steps[0].get("with", {})
    assert str(trivy_args.get("severity")) == "CRITICAL,HIGH"
    assert str(trivy_args.get("exit-code")) == "1"

    sign_job = jobs["sign"]
    assert "cosign-installer" in str(sign_job)
    assert "if" in sign_job, "Le job de signature doit etre conditionnel"
    assert "id-token" in sign_job.get("permissions", {})


def test_ci_frontend_steps_are_optional() -> None:
    """Le build frontend est conditionne a la presence de package.json."""
    workflow = _load_yaml(_REPO_ROOT / ".github" / "workflows" / "ci.yml")
    frontend_steps = [
        step
        for step in workflow["jobs"]["docker"]["steps"]
        if "frontend.Dockerfile" in str(step.get("run", ""))
    ]
    assert frontend_steps, "Etape de build frontend absente"
    assert "hashFiles" in str(frontend_steps[0].get("if", ""))


# =============================================================================
# Dockerfiles
# =============================================================================


def test_dockerfiles_exist() -> None:
    names = {path.name for path in _DOCKERFILES}
    assert {"backend.Dockerfile", "frontend.Dockerfile"} <= names


@pytest.mark.parametrize("dockerfile", _DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_has_no_latest_image(dockerfile: Path) -> None:
    """Aucune image ``:latest`` (reproductibilite / SLSA)."""
    for number, line in _dockerfile_instructions(dockerfile):
        if line.upper().startswith(("FROM ", "ARG ")):
            assert (
                ":latest" not in line.lower()
            ), f"{dockerfile.name}:{number} utilise :latest"


@pytest.mark.parametrize("dockerfile", _DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_final_user_is_non_root(dockerfile: Path) -> None:
    """La derniere instruction USER doit etre un UID/GID non-root explicite."""
    users = [
        line
        for _, line in _dockerfile_instructions(dockerfile)
        if line.upper().startswith("USER ")
    ]
    assert users, f"{dockerfile.name} ne definit aucun USER"
    final_user = users[-1].split(None, 1)[1].strip()
    assert final_user not in {
        "root",
        "0",
        "0:0",
        "root:root",
    }, f"{dockerfile.name} s'execute en root ({final_user})"
    first = final_user.split(":", 1)[0]
    assert (
        first.isdigit()
    ), f"{dockerfile.name}: USER doit etre numerique ({final_user})"
    assert int(first) > 0, f"{dockerfile.name}: UID 0 interdit"


def test_backend_dockerfile_hardening() -> None:
    dockerfile = _DOCKER_DIR / "backend.Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    instructions = _dockerfile_instructions(dockerfile)
    assert "gcr.io/distroless/python3-debian12:nonroot" in content
    assert "PYTHONDONTWRITEBYTECODE=1" in content
    assert "USER 65532:65532" in content
    assert "HEALTHCHECK" in content
    # Aucune instruction SHELL : conteneur sans shell interactif.
    assert not any(line.upper().startswith("SHELL ") for _, line in instructions)
    # Le code applicatif et les dependances sont copies depuis le builder.
    assert "COPY --from=builder" in content
    assert "requirements.txt" in content
    # Aucun .env ne doit entrer dans l'image.
    copy_lines = [
        line for _, line in instructions if line.upper().startswith(("COPY", "ADD"))
    ]
    assert not any(".env" in line for line in copy_lines)


def test_frontend_dockerfile_hardening() -> None:
    content = (_DOCKER_DIR / "frontend.Dockerfile").read_text(encoding="utf-8")
    assert "node:22-alpine" in content
    assert "nginxinc/nginx-unprivileged" in content
    assert "USER 101:101" in content
    assert "EXPOSE 8080" in content
    assert "HEALTHCHECK" in content
    assert "nginx.conf" in content


@pytest.mark.parametrize("dockerfile", _DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_has_ignore_file(dockerfile: Path) -> None:
    """Un .dockerignore dedie evite d'envoyer .env / venv au demon Docker."""
    ignore = dockerfile.with_name(f"{dockerfile.name}.dockerignore")
    assert ignore.is_file(), f"{ignore.name} manquant"
    assert "*" in ignore.read_text(encoding="utf-8")


def test_nginx_config_hardening() -> None:
    config = (_DOCKER_DIR / "nginx.conf").read_text(encoding="utf-8")
    assert "listen 8080" in config
    assert "pid /tmp/nginx.pid" in config
    assert "client_body_temp_path /tmp/" in config
    assert "try_files $uri $uri/ /index.html" in config
    assert "Content-Security-Policy" in config
    assert "default-src 'self'" in config
    assert "Strict-Transport-Security" in config
    assert "frame-ancestors 'none'" in config
    assert "server_tokens off" in config
    # Pas de add_header dans les locations (heritage des en-tetes de securite).
    locations = re.findall(r"location[^\{]*\{([^}]*)\}", config)
    for block in locations:
        assert (
            "add_header" not in block
        ), "add_header dans location casse l'heritage CSP/HSTS"


# =============================================================================
# Terraform
# =============================================================================


def test_terraform_files_are_present() -> None:
    expected = {
        "versions.tf",
        "variables.tf",
        "main.tf",
        "outputs.tf",
        "terraform.tfvars.example",
        "README.md",
    }
    assert expected <= {path.name for path in _TERRAFORM_DIR.iterdir()}


def test_terraform_is_in_scope_and_hardened() -> None:
    main = (_TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    for network in ("net_ot", "net_it", "net_dmz"):
        assert f'resource "docker_network" "{network}"' in main
    assert "no-new-privileges:true" in main
    assert 'drop = ["ALL"]' in main
    assert "read_only = true" in main
    assert "healthcheck {" in main
    # Aucun secret en clair dans les fichiers versionnes.
    for name in ("main.tf", "variables.tf", "terraform.tfvars.example"):
        text = (_TERRAFORM_DIR / name).read_text(encoding="utf-8")
        assert "SecuriGlass_Admin_2026" not in text, f"{name} contient un secret"


def test_terraform_tfvars_example_has_no_real_secret() -> None:
    text = (_TERRAFORM_DIR / "terraform.tfvars.example").read_text(encoding="utf-8")
    assert "CHANGE_ME" in text or "change_me" in text
    assert "postgres_password" in text
    assert "tde_encryption_key" in text


@pytest.mark.skipif(
    shutil.which("terraform") is None,
    reason="terraform absent du PATH : validation fmt impossible (skip explicite)",
)
def test_terraform_fmt_is_clean() -> None:
    result = subprocess.run(
        ["terraform", "fmt", "-check", "-recursive", "."],
        cwd=_TERRAFORM_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), f"terraform fmt -check echoue :\n{result.stdout}{result.stderr}"


# =============================================================================
# Ansible
# =============================================================================


def test_ansible_role_structure() -> None:
    required = [
        _ANSIBLE_DIR / "playbook-hardening.yml",
        _ANSIBLE_DIR / "inventory.example.ini",
        _ANSIBLE_DIR / "ansible.cfg",
        _CIS_ROLE_DIR / "tasks" / "main.yml",
        _CIS_ROLE_DIR / "handlers" / "main.yml",
        _CIS_ROLE_DIR / "defaults" / "main.yml",
        _CIS_ROLE_DIR / "meta" / "main.yml",
    ]
    for path in required:
        assert path.is_file(), f"Fichier Ansible manquant : {path}"

    tasks = {
        "packages.yml",
        "ssh.yml",
        "sysctl.yml",
        "auditd.yml",
        "journald.yml",
        "permissions.yml",
        "umask.yml",
        "services.yml",
        "banner.yml",
    }
    present = {path.name for path in (_CIS_ROLE_DIR / "tasks").glob("*.yml")}
    assert tasks <= present, f"Taches manquantes : {tasks - present}"

    templates = {path.name for path in (_CIS_ROLE_DIR / "templates").glob("*.j2")}
    for name in ("sshd_config.j2", "sysctl-hardening.conf.j2", "audit.rules.j2"):
        assert name in templates, f"Template manquant : {name}"


def test_ansible_yaml_is_parsable() -> None:
    yaml_files = [
        path
        for path in _ANSIBLE_DIR.rglob("*.yml")
        if "templates" not in path.parts and "files" not in path.parts
    ]
    assert yaml_files, "Aucun YAML Ansible"
    for path in yaml_files:
        document = _load_yaml(path)
        assert document is not None, f"{path} est vide ou invalide"


def test_ansible_playbook_and_cfg() -> None:
    playbook = _load_yaml(_ANSIBLE_DIR / "playbook-hardening.yml")
    assert isinstance(playbook, list) and playbook
    play = playbook[0]
    assert play["hosts"] == "linux_hardening"
    assert play.get("become") is True
    role_names = [
        role["role"] if isinstance(role, dict) else role for role in play["roles"]
    ]
    assert "cis_linux" in role_names

    cfg = (_ANSIBLE_DIR / "ansible.cfg").read_text(encoding="utf-8")
    assert "roles_path" in cfg
    assert "vault_identity_list" in cfg
    assert "no_log" in cfg.lower()


def test_ansible_no_plaintext_secret() -> None:
    for path in _ANSIBLE_DIR.rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "SecuriGlass_Admin_2026" not in text, f"Secret en clair dans {path}"


# =============================================================================
# Semgrep / Trivy
# =============================================================================


def test_semgrep_rules_are_valid() -> None:
    document = _load_yaml(_SECURITY_DIR / "semgrep.yml")
    rules = document.get("rules")
    assert isinstance(rules, list) and len(rules) >= 8

    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "Identifiants Semgrep dupliques"
    for rule in rules:
        assert rule.get("languages"), f"{rule['id']} sans langage"
        assert rule.get("message"), f"{rule['id']} sans message"
        assert rule.get("severity") in {"ERROR", "WARNING", "INFO"}
        assert rule.get("metadata"), f"{rule['id']} sans metadata"
        assert any(key in rule for key in ("pattern", "patterns", "pattern-either"))

    expected_ids = {
        "securiglass-no-eval-python",
        "securiglass-hardcoded-secret-python",
        "securiglass-subprocess-shell-true",
        "securiglass-sql-string-concatenation",
        "securiglass-tls-verify-disabled",
        "securiglass-weak-hash",
    }
    assert expected_ids <= set(ids)


def test_trivy_policy() -> None:
    policy = _load_yaml(_SECURITY_DIR / "trivy.yaml")
    assert policy["severity"] == ["CRITICAL", "HIGH"]
    assert policy["ignore-unfixed"] is False
    assert policy["exit-code"] == 1
    scanners = set(policy["scan"]["scanners"])
    assert {"vuln", "secret", "misconfig"} <= scanners
