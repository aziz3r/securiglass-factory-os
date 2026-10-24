/*
 * SecuriGlass Factory OS - Décodage / encodage Modbus TCP (MBAP + PDU).
 *
 * Principe : aucune confiance dans les octets reçus. Toute incohérence de
 * longueur, de protocole, de quantité ou d'adresse est rejetée AVANT tout
 * accès mémoire. Aucune allocation dynamique.
 */

#include "securiglass_plc.h"

#include <string.h>

#define MB_FC_READ_HOLDING 0x03u
#define MB_FC_READ_INPUT 0x04u
#define MB_FC_WRITE_SINGLE 0x06u
#define MB_FC_WRITE_MULTIPLE 0x10u

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void write_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFFu);
}

int modbus_parse_adu(const uint8_t *adu, size_t adu_len, struct modbus_request *request)
{
    uint16_t length_field;
    size_t expected;

    if (adu == NULL || request == NULL) {
        return -1;
    }
    if (adu_len < MBAP_HEADER_LEN + 1u || adu_len > MB_MAX_ADU) {
        return -1;
    }

    memset(request, 0, sizeof(*request));
    request->transaction_id = read_u16(&adu[0]);
    request->protocol_id = read_u16(&adu[2]);
    length_field = read_u16(&adu[4]);
    request->unit_id = adu[6];

    /* Protocole Modbus = 0 uniquement (pas de multiplexage). */
    if (request->protocol_id != 0u) {
        return -1;
    }
    /* Le champ longueur compte l'unit id + la PDU. */
    if (length_field < 2u || length_field > MB_MAX_PDU) {
        return -1;
    }

    expected = 6u + (size_t)length_field;
    if (adu_len != expected) {
        return -1;
    }

    request->function_code = adu[7];
    request->pdu_data = &adu[8];
    request->pdu_len = (size_t)length_field - 2u;
    return 0;
}

int modbus_build_exception(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    uint8_t function_code,
    uint8_t exception_code)
{
    if (out == NULL || request == NULL || out_cap < 9u) {
        return -1;
    }
    write_u16(&out[0], request->transaction_id);
    write_u16(&out[2], 0u);
    write_u16(&out[4], 3u);
    out[6] = request->unit_id;
    out[7] = (uint8_t)(function_code | 0x80u);
    out[8] = exception_code;
    return 9;
}

static int build_read_response(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    const struct plant_state *plant)
{
    uint16_t start;
    uint16_t quantity;
    uint16_t i;
    size_t total;

    if (request->pdu_len != 4u) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    start = read_u16(&request->pdu_data[0]);
    quantity = read_u16(&request->pdu_data[2]);

    if (quantity == 0u || quantity > MB_MAX_READ_REGS) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    /* Dépassement d'adresse : (start + quantity) doit rester dans la carte. */
    if ((uint32_t)start + (uint32_t)quantity > (uint32_t)REG_COUNT) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_ADDRESS);
    }

    total = 9u + (size_t)quantity * 2u;
    if (out_cap < total) {
        return -1;
    }

    write_u16(&out[0], request->transaction_id);
    write_u16(&out[2], 0u);
    write_u16(&out[4], (uint16_t)(3u + quantity * 2u));
    out[6] = request->unit_id;
    out[7] = request->function_code;
    out[8] = (uint8_t)(quantity * 2u);

    for (i = 0u; i < quantity; i++) {
        uint16_t value = plant_read_register(plant, (uint16_t)(start + i));
        write_u16(&out[9u + (size_t)i * 2u], value);
    }
    return (int)total;
}

static int build_write_single_response(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    struct plant_state *plant)
{
    uint16_t address;
    uint16_t value;
    uint8_t exception;

    if (request->pdu_len != 4u || out_cap < 12u) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    address = read_u16(&request->pdu_data[0]);
    value = read_u16(&request->pdu_data[2]);
    exception = plant_write_register(plant, address, value);
    if (exception != MB_EXC_NONE) {
        return modbus_build_exception(out, out_cap, request, request->function_code, exception);
    }

    /* Écho normalisé de la requête (12 octets). */
    write_u16(&out[0], request->transaction_id);
    write_u16(&out[2], 0u);
    write_u16(&out[4], 6u);
    out[6] = request->unit_id;
    out[7] = request->function_code;
    write_u16(&out[8], address);
    write_u16(&out[10], value);
    return 12;
}

static int build_write_multiple_response(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    struct plant_state *plant)
{
    uint16_t start;
    uint16_t quantity;
    uint8_t byte_count;
    uint16_t i;

    if (request->pdu_len < 5u || out_cap < 12u) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    start = read_u16(&request->pdu_data[0]);
    quantity = read_u16(&request->pdu_data[2]);
    byte_count = request->pdu_data[4];

    if (quantity == 0u || quantity > MB_MAX_WRITE_REGS) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    /* Cohérence stricte : 1 octet de compteur + 2 octets par registre. */
    if ((size_t)byte_count != (size_t)quantity * 2u || request->pdu_len != 5u + (size_t)byte_count) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_VALUE);
    }
    if ((uint32_t)start + (uint32_t)quantity > (uint32_t)REG_COUNT) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_DATA_ADDRESS);
    }

    /*
     * Écriture atomique : on valide TOUS les registres avant d'en appliquer un
     * seul, afin de ne jamais laisser le procédé dans un état partiellement écrit.
     */
    for (i = 0u; i < quantity; i++) {
        uint16_t address = (uint16_t)(start + i);
        if (address < REG_FIRST_WRITABLE || address > REG_LAST_WRITABLE) {
            return modbus_build_exception(out, out_cap, request, request->function_code,
                                          MB_EXC_ILLEGAL_DATA_ADDRESS);
        }
    }
    for (i = 0u; i < quantity; i++) {
        uint16_t address = (uint16_t)(start + i);
        uint16_t value = read_u16(&request->pdu_data[5u + (size_t)i * 2u]);
        uint8_t exception = plant_write_register(plant, address, value);
        if (exception != MB_EXC_NONE) {
            return modbus_build_exception(out, out_cap, request, request->function_code,
                                          exception);
        }
    }

    write_u16(&out[0], request->transaction_id);
    write_u16(&out[2], 0u);
    write_u16(&out[4], 6u);
    out[6] = request->unit_id;
    out[7] = request->function_code;
    write_u16(&out[8], start);
    write_u16(&out[10], quantity);
    return 12;
}

int modbus_build_response(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    struct plant_state *plant)
{
    if (out == NULL || request == NULL || plant == NULL || out_cap < 9u) {
        return -1;
    }

    /* Contrôle d'unité : une trame destinée à un autre automate est refusée. */
    if (request->unit_id != plant->unit_id) {
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_GATEWAY_TARGET_FAILED);
    }

    switch (request->function_code) {
    case MB_FC_READ_HOLDING:
    case MB_FC_READ_INPUT:
        return build_read_response(out, out_cap, request, plant);
    case MB_FC_WRITE_SINGLE:
        return build_write_single_response(out, out_cap, request, plant);
    case MB_FC_WRITE_MULTIPLE:
        return build_write_multiple_response(out, out_cap, request, plant);
    default:
        return modbus_build_exception(out, out_cap, request, request->function_code,
                                      MB_EXC_ILLEGAL_FUNCTION);
    }
}
