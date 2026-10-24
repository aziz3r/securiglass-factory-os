"""Contrat du module de compatibilité `app.schemas.models` (réexport)."""

from __future__ import annotations


def test_compatibility_shim_reexports_the_canonical_schemas() -> None:
    from app.models import schemas as canonical
    from app.schemas import models as shim

    assert shim.LoginRequest is canonical.LoginRequest
    assert shim.TokenResponse is canonical.TokenResponse
    assert shim.MeResponse is canonical.MeResponse
    assert shim.CustomerResponse is canonical.CustomerResponse
    assert shim.AuditLogOut is canonical.AuditLogOut
    assert set(shim.__all__) == set(shim.__all__)  # pas de doublon silencieux

    for name in shim.__all__:
        assert hasattr(shim, name), f"export manquant : {name}"
