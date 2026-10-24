/*
 * SecuriGlass Factory OS - Tests unitaires C du démon PLC.
 *
 * Exécuté nativement et sous Valgrind (cible `make valgrind`) : toute fuite ou
 * toute lecture non initialisée fait échouer la CI. Aucun framework externe :
 * le binaire retourne 0 si et seulement si tous les contrôles passent.
 */

#include "securiglass_plc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        g_checks++;                                                                    \
        if (!(cond)) {                                                                 \
            g_failures++;                                                              \
            fprintf(stderr, "ECHEC %s:%d : %s\n", __FILE__, __LINE__, #cond);          \
        }                                                                              \
    } while (0)

static size_t make_adu(
    uint8_t *adu,
    uint16_t transaction_id,
    uint16_t protocol_id,
    uint8_t unit_id,
    const uint8_t *pdu,
    size_t pdu_len)
{
    uint16_t length_field = (uint16_t)(1u + pdu_len);

    adu[0] = (uint8_t)(transaction_id >> 8);
    adu[1] = (uint8_t)(transaction_id & 0xFFu);
    adu[2] = (uint8_t)(protocol_id >> 8);
    adu[3] = (uint8_t)(protocol_id & 0xFFu);
    adu[4] = (uint8_t)(length_field >> 8);
    adu[5] = (uint8_t)(length_field & 0xFFu);
    adu[6] = unit_id;
    memcpy(adu + 7, pdu, pdu_len);
    return 7u + pdu_len;
}

static void test_plant_init(void)
{
    struct plant_state plant;

    plant_init(&plant, 1u, 42u);
    CHECK(plant.unit_id == 1u);
    CHECK((plant.regs[REG_STATUS] & STATUS_RUNNING) != 0u);
    CHECK(plant.regs[REG_TEMP_ZONE1] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_CONVEYOR_SPEED] <= CONVEYOR_MAX_X100);
    CHECK(plant.regs[REG_SEQUENCE] == 0u);
}

static void test_plant_stays_in_bounds(void)
{
    struct plant_state plant;
    int i;

    plant_init(&plant, 1u, 7u);
    for (i = 0; i < 5000; i++) {
        plant_step(&plant);
    }
    CHECK(plant.regs[REG_TEMP_ZONE1] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_TEMP_ZONE2] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_TEMP_ZONE3] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_TEMP_ZONE4] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_PYROMETER] <= TEMP_MAX_X10);
    CHECK(plant.regs[REG_QUENCH_PRESSURE] <= QUENCH_MAX_X100);
    CHECK(plant.regs[REG_CONVEYOR_SPEED] <= CONVEYOR_MAX_X100);
    CHECK(plant.regs[REG_SEQUENCE] == (uint16_t)(5000 & 0xFFFF));
}

static void test_modbus_parse_valid_read(void)
{
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x0Au};
    struct modbus_request request;
    size_t adu_len = make_adu(adu, 0x1234u, 0u, 1u, pdu, sizeof(pdu));

    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    CHECK(request.transaction_id == 0x1234u);
    CHECK(request.protocol_id == 0u);
    CHECK(request.unit_id == 1u);
    CHECK(request.function_code == 0x03u);
    CHECK(request.pdu_len == 4u);
}

static void test_modbus_parse_rejects_bad_frames(void)
{
    uint8_t adu[24];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x01u};
    struct modbus_request request;
    size_t adu_len = make_adu(adu, 1u, 0u, 1u, pdu, sizeof(pdu));

    CHECK(modbus_parse_adu(NULL, adu_len, &request) == -1);
    CHECK(modbus_parse_adu(adu, 0u, &request) == -1);
    CHECK(modbus_parse_adu(adu, 6u, &request) == -1);
    /* Tronquée */
    CHECK(modbus_parse_adu(adu, adu_len - 1u, &request) == -1);
    /* Protocole non nul */
    {
        uint8_t bad[24];
        size_t len = make_adu(bad, 1u, 0x0001u, 1u, pdu, sizeof(pdu));
        CHECK(modbus_parse_adu(bad, len, &request) == -1);
    }
    /* Champ longueur incohérent (0) */
    {
        uint8_t bad[16] = {0};
        bad[6] = 1u;
        bad[7] = 0x03u;
        CHECK(modbus_parse_adu(bad, 8u, &request) == -1);
    }
    /* Champ longueur trop grand */
    {
        uint8_t bad[16] = {0};
        bad[4] = 0xFFu;
        bad[5] = 0xFFu;
        CHECK(modbus_parse_adu(bad, 16u, &request) == -1);
    }
}

static void test_read_holding_registers(void)
{
    struct plant_state plant;
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x02u};
    struct modbus_request request;
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;

    plant_init(&plant, 1u, 1u);
    adu_len = make_adu(adu, 0x2222u, 0u, 1u, pdu, sizeof(pdu));
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 13);
    CHECK(response[0] == 0x22u && response[1] == 0x22u);
    CHECK(response[4] == 0x00u && response[5] == 0x07u); /* 3 + 2*2 */
    CHECK(response[6] == 1u);
    CHECK(response[7] == 0x03u);
    CHECK(response[8] == 4u);
    CHECK(response[9] == (uint8_t)(plant.regs[REG_TEMP_ZONE1] >> 8));
}

static void test_read_out_of_range_is_exception(void)
{
    struct plant_state plant;
    uint8_t adu[16];
    uint8_t pdu[4];
    struct modbus_request request;
    uint8_t response[MB_MAX_ADU];
    int response_len;

    plant_init(&plant, 1u, 1u);
    /* start = 65530, qty = 10 : dépasse la carte de registres */
    pdu[0] = 0xFFu;
    pdu[1] = 0xFAu;
    pdu[2] = 0x00u;
    pdu[3] = 0x0Au;
    {
        size_t adu_len = make_adu(adu, 3u, 0u, 1u, pdu, sizeof(pdu));
        CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    }
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 9);
    CHECK(response[7] == (uint8_t)(0x03u | 0x80u));
    CHECK(response[8] == MB_EXC_ILLEGAL_DATA_ADDRESS);
}

static void test_read_quantity_limits(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x00u}; /* quantité nulle */
    uint8_t response[MB_MAX_ADU];
    int response_len;
    size_t adu_len;

    plant_init(&plant, 1u, 1u);
    adu_len = make_adu(adu, 4u, 0u, 1u, pdu, sizeof(pdu));
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 9);
    CHECK(response[8] == MB_EXC_ILLEGAL_DATA_VALUE);
}

static void test_write_single_register(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x14u, 0x17u, 0x70u}; /* reg 20 = 6000 (600.0 C) */
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;

    plant_init(&plant, 1u, 1u);
    adu_len = make_adu(adu, 5u, 0u, 1u, pdu, sizeof(pdu));
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 12);
    CHECK(plant.regs[REG_SETPOINT_ZONE1] == 6000u);
}

static void test_write_single_rejects_read_only_and_out_of_range(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[16];
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;

    plant_init(&plant, 1u, 1u);

    /* Registre de télémétrie (non inscriptible) */
    {
        uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x01u};
        adu_len = make_adu(adu, 6u, 0u, 1u, pdu, sizeof(pdu));
        CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
        response_len = modbus_build_response(response, sizeof(response), &request, &plant);
        CHECK(response_len == 9);
        CHECK(response[8] == MB_EXC_ILLEGAL_DATA_ADDRESS);
    }
    /* Consigne de température hors plage */
    {
        uint8_t pdu[4] = {0x00u, 0x14u, 0xFFu, 0xFFu};
        adu_len = make_adu(adu, 7u, 0u, 1u, pdu, sizeof(pdu));
        CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
        response_len = modbus_build_response(response, sizeof(response), &request, &plant);
        CHECK(response_len == 9);
        CHECK(response[8] == MB_EXC_ILLEGAL_DATA_VALUE);
    }
}

static void test_write_multiple_is_atomic(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[32];
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;
    uint16_t original;

    plant_init(&plant, 1u, 1u);
    original = plant.regs[REG_SETPOINT_ZONE1];
    /* reg 20 = valide, reg 21 = 0xFFFF (invalide) : aucune écriture ne doit passer. */
    {
        uint8_t pdu[9] = {0x00u, 0x14u, 0x00u, 0x02u, 0x04u, 0x17u, 0x70u, 0xFFu, 0xFFu};
        adu_len = make_adu(adu, 8u, 0u, 1u, pdu, sizeof(pdu));
        CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
        response_len = modbus_build_response(response, sizeof(response), &request, &plant);
        CHECK(response_len == 9);
        CHECK(response[8] == MB_EXC_ILLEGAL_DATA_VALUE);
        CHECK(plant.regs[REG_SETPOINT_ZONE1] == original);
    }
}

static void test_write_multiple_byte_count_mismatch(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[32];
    uint8_t response[MB_MAX_ADU];
    uint8_t pdu[9] = {0x00u, 0x14u, 0x00u, 0x02u, 0x03u, 0x17u, 0x70u, 0x17u, 0x70u};
    size_t adu_len = make_adu(adu, 9u, 0u, 1u, pdu, sizeof(pdu));
    int response_len;

    plant_init(&plant, 1u, 1u);
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 9);
    CHECK(response[8] == MB_EXC_ILLEGAL_DATA_VALUE);
}

static void test_emergency_stop_interlock(void)
{
    struct plant_state plant;
    uint16_t setpoint_before;

    plant_init(&plant, 1u, 1u);
    setpoint_before = plant.regs[REG_SETPOINT_ZONE1];
    CHECK(plant_write_register(&plant, REG_COMMAND, CMD_EMERGENCY_STOP) == MB_EXC_NONE);
    CHECK(plant_is_emergency_stopped(&plant));
    CHECK(plant_write_register(&plant, REG_SETPOINT_ZONE1, 6500u) == MB_EXC_SERVER_FAILURE);
    CHECK(plant.regs[REG_SETPOINT_ZONE1] == setpoint_before);
    CHECK(plant_write_register(&plant, REG_COMMAND, CMD_RESET) == MB_EXC_NONE);
    CHECK(!plant_is_emergency_stopped(&plant));
}

static void test_unknown_function_is_exception(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x01u};
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;

    plant_init(&plant, 1u, 1u);
    adu_len = make_adu(adu, 10u, 0u, 1u, pdu, sizeof(pdu));
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    request.function_code = 0x2Bu; /* non supporté */
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 9);
    CHECK(response[7] == (uint8_t)(0x2Bu | 0x80u));
    CHECK(response[8] == MB_EXC_ILLEGAL_FUNCTION);
}

static void test_wrong_unit_id_is_refused(void)
{
    struct plant_state plant;
    struct modbus_request request;
    uint8_t adu[16];
    uint8_t pdu[4] = {0x00u, 0x00u, 0x00u, 0x01u};
    uint8_t response[MB_MAX_ADU];
    size_t adu_len;
    int response_len;

    plant_init(&plant, 1u, 1u);
    adu_len = make_adu(adu, 11u, 0u, 9u, pdu, sizeof(pdu));
    CHECK(modbus_parse_adu(adu, adu_len, &request) == 0);
    response_len = modbus_build_response(response, sizeof(response), &request, &plant);
    CHECK(response_len == 9);
    CHECK(response[8] == MB_EXC_GATEWAY_TARGET_FAILED);
}

static void test_null_safety(void)
{
    uint8_t response[8];

    CHECK(modbus_parse_adu(NULL, 8u, NULL) == -1);
    CHECK(modbus_build_response(NULL, 0u, NULL, NULL) == -1);
    CHECK(modbus_build_exception(response, sizeof(response), NULL, 3u, 1u) == -1);
    CHECK(plant_read_register(NULL, 0u) == 0u);
    CHECK(plant_write_register(NULL, REG_SETPOINT_ZONE1, 1u) == MB_EXC_SERVER_FAILURE);
    CHECK(plant_is_emergency_stopped(NULL));
    plant_step(NULL);
    plant_init(NULL, 1u, 1u);
}

int main(void)
{
    test_plant_init();
    test_plant_stays_in_bounds();
    test_modbus_parse_valid_read();
    test_modbus_parse_rejects_bad_frames();
    test_read_holding_registers();
    test_read_out_of_range_is_exception();
    test_read_quantity_limits();
    test_write_single_register();
    test_write_single_rejects_read_only_and_out_of_range();
    test_write_multiple_is_atomic();
    test_write_multiple_byte_count_mismatch();
    test_emergency_stop_interlock();
    test_unknown_function_is_exception();
    test_wrong_unit_id_is_refused();
    test_null_safety();

    if (g_failures != 0) {
        fprintf(stderr, "ECHEC : %d/%d contrôles\n", g_failures, g_checks);
        return 1;
    }
    printf("OK : %d contrôles\n", g_checks);
    return 0;
}
