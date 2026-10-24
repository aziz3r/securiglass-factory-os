"""Tests unitaires des schémas Pydantic v2 stricts (OWASP ASVS & IEC 62443)."""

import uuid
import pytest
from pydantic import ValidationError

from app.models.schemas import (
    CustomerCreate,
    CustomerResponse,
    LoginRequest,
    TokenResponse,
    ABACPolicyCreate,
)


def test_login_request_rejects_extra_fields() -> None:
    # Doit lever ValidationError si un champ non déclaré est injecté (Mass Assignment Protection)
    with pytest.raises(ValidationError):
        LoginRequest(
            username="admin",
            password="secret_password",
            extra_malicious_field="injection",  # type: ignore[call-arg]
        )


def test_customer_create_validates_regex_and_email() -> None:
    # Email invalide
    with pytest.raises(ValidationError):
        CustomerCreate(
            company_name="Acme Glass",
            contact_name="Bob",
            email="not-an-email",  # type: ignore[arg-type]
            country_code="FR",
        )

    # Téléphone invalide
    with pytest.raises(ValidationError):
        CustomerCreate(
            company_name="Acme Glass",
            contact_name="Bob",
            email="bob@acme.fr",
            phone="abc-invalid-phone",
            country_code="FR",
        )

    # Valide
    customer = CustomerCreate(
        company_name="Saint-Gobain Glass B2B",
        contact_name="Henri Delacroix",
        email="h.delacroix@saint-gobain.com",
        phone="+33 1 47 62 30 00",
        vat_number="FR12345678901",
        country_code="FR",
    )
    assert customer.company_name == "Saint-Gobain Glass B2B"


def test_abac_policy_create_effect_validation() -> None:
    # Effect doit être 'ALLOW' ou 'DENY'
    with pytest.raises(ValidationError):
        ABACPolicyCreate(
            policy_name="POL_01",
            effect="MAYBE",  # type: ignore[arg-type]
            subject_role="OT_OPERATOR",
            action_verb="ot:control:write",
            resource_urn="urn:securiglass:ot:*",
            rule_condition={"equals": {"x": 1}},
        )

    # Valide
    pol = ABACPolicyCreate(
        policy_name="POL_01",
        effect="DENY",
        subject_role="OT_OPERATOR",
        action_verb="ot:control:write",
        resource_urn="urn:securiglass:ot:*",
        rule_condition={"equals": {"x": 1}},
    )
    assert pol.effect == "DENY"
