"""Endpoints de gestion des clients B2B (Démonstration TDE AES-256-GCM - RGPD Art. 32).

Les données à caractère personnel (`contact_name`, `email`, `phone`) sont :
1. Chiffrées symétriquement avant toute écriture en base.
2. Déchiffrées dynamiquement à la lecture uniquement pour les rôles autorisés (PoLP).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import Conn, CurrentUserDep, client_ip, require_roles
from app.models.schemas import CustomerCreate, CustomerOut, CustomerResponse
from app.services import audit_service
from app.services.tde_service import TDEService, get_tde_service

router = APIRouter(prefix="/api/v1/customers", tags=["customers"])

# Gardes RBAC conformes à la matrice RBAC_ABAC_MATRIX.md
CustomerCreator = Annotated[CurrentUserDep, Depends(require_roles("PLANT_MANAGER"))]
CustomerViewer = Annotated[
    CurrentUserDep,
    Depends(require_roles("PLANT_MANAGER", "SUPER_ADMIN", "SECURITY_AUDITOR")),
]


@router.post(
    "",
    response_model=CustomerResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Création d'un client avec chiffrement TDE au repos",
)
async def create_customer(
    body: CustomerCreate,
    request: Request,
    conn: Conn,
    user: CustomerCreator,
    tde: Annotated[TDEService, Depends(get_tde_service)],
) -> CustomerResponse:
    """Chiffre les champs PII en AES-256-GCM et insère l'enregistrement dans it_data.customers."""
    # Chiffrement TDE transparent des colonnes RGPD sensibles
    encrypted_pii = tde.encrypt_customer_pii(
        contact_name=body.contact_name,
        email=str(body.email),
        phone=body.phone,
    )

    row = await conn.fetchrow(
        """
        INSERT INTO it_data.customers (
            company_name, contact_name_encrypted, email_encrypted,
            phone_encrypted, vat_number, country_code
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, company_name, vat_number, country_code, is_active, created_at
        """,
        body.company_name,
        encrypted_pii.contact_name_encrypted,
        encrypted_pii.email_encrypted,
        encrypted_pii.phone_encrypted,
        body.vat_number,
        body.country_code,
    )

    if row is None:
        raise RuntimeError("Échec de l'enregistrement du client en base")
    customer_id = row["id"]

    await audit_service.record_event(
        conn,
        event_type="CUSTOMER_CREATE",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="CREATE",
        resource=f"it_data.customers/{customer_id}",
        outcome="SUCCESS",
        details={"company_name": body.company_name, "tde_encrypted": True},
    )

    return CustomerResponse(
        id=customer_id,
        company_name=row["company_name"],
        contact_name=body.contact_name,
        email=body.email,
        phone=body.phone,
        vat_number=row["vat_number"],
        country_code=row["country_code"],
        is_active=row["is_active"],
        created_at=row["created_at"],
    )


@router.get(
    "",
    response_model=list[CustomerResponse],
    status_code=status.HTTP_200_OK,
    summary="Liste des clients avec déchiffrement TDE à la volée",
)
async def list_customers(
    request: Request,
    conn: Conn,
    user: CustomerViewer,
    tde: Annotated[TDEService, Depends(get_tde_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CustomerResponse]:
    """Récupère les enregistrements clients et déchiffre les données personnelles pour consultation."""
    rows = await conn.fetch(
        """
        SELECT id, company_name, contact_name_encrypted, email_encrypted,
               phone_encrypted, vat_number, country_code, is_active, created_at
        FROM it_data.customers
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        """,
        limit,
        offset,
    )

    results: list[CustomerResponse] = []
    for r in rows:
        decrypted = tde.decrypt_customer_pii(
            contact_name_encrypted=r["contact_name_encrypted"],
            email_encrypted=r["email_encrypted"],
            phone_encrypted=r["phone_encrypted"],
        )
        results.append(
            CustomerResponse(
                id=r["id"],
                company_name=r["company_name"],
                contact_name=decrypted.contact_name,
                email=decrypted.email,
                phone=decrypted.phone,
                vat_number=r["vat_number"],
                country_code=r["country_code"],
                is_active=r["is_active"],
                created_at=r["created_at"],
            )
        )

    await audit_service.record_event(
        conn,
        event_type="CUSTOMER_READ_BATCH",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="READ",
        resource="it_data.customers",
        outcome="SUCCESS",
        details={"records_count": len(results), "tde_decrypted": True},
    )

    return results


@router.get(
    "/{customer_id}",
    response_model=CustomerResponse,
    status_code=status.HTTP_200_OK,
    summary="Consultation détaillée d'un client (déchiffrement TDE)",
)
async def get_customer(
    customer_id: uuid.UUID,
    request: Request,
    conn: Conn,
    user: CustomerViewer,
    tde: Annotated[TDEService, Depends(get_tde_service)],
) -> CustomerResponse:
    """Récupère un client unique et déchiffre ses colonnes sensibles."""
    row = await conn.fetchrow(
        """
        SELECT id, company_name, contact_name_encrypted, email_encrypted,
               phone_encrypted, vat_number, country_code, is_active, created_at
        FROM it_data.customers
        WHERE id = $1
        """,
        customer_id,
    )

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client introuvable",
        )

    decrypted = tde.decrypt_customer_pii(
        contact_name_encrypted=row["contact_name_encrypted"],
        email_encrypted=row["email_encrypted"],
        phone_encrypted=row["phone_encrypted"],
    )

    await audit_service.record_event(
        conn,
        event_type="CUSTOMER_READ_SINGLE",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="READ",
        resource=f"it_data.customers/{customer_id}",
        outcome="SUCCESS",
        details={"tde_decrypted": True},
    )

    return CustomerResponse(
        id=row["id"],
        company_name=row["company_name"],
        contact_name=decrypted.contact_name,
        email=decrypted.email,
        phone=decrypted.phone,
        vat_number=row["vat_number"],
        country_code=row["country_code"],
        is_active=row["is_active"],
        created_at=row["created_at"],
    )
