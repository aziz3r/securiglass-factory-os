/*
 * SecuriGlass Factory OS - Démon PLC (simulateur d'automate de ligne de trempe)
 * Purdue niveau 1/2 - IEC 62443 - Modbus TCP
 *
 * Contraintes de sûreté mémoire :
 *  - aucune allocation dynamique après l'initialisation ;
 *  - tous les tampons sont de taille fixe et bornés (ADU Modbus = 260 octets) ;
 *  - aucune écriture hors bornes : tout index de registre est validé ;
 *  - aucun thread : un unique thread d'événements, donc aucune course de données.
 */
#ifndef SECURIGLASS_PLC_H
#define SECURIGLASS_PLC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MBAP_HEADER_LEN 7
#define MB_MAX_ADU 260
#define MB_MAX_PDU 253
#define MB_MAX_READ_REGS 125
#define MB_MAX_WRITE_REGS 123
#define MAX_CLIENTS 16
#define PLANT_NUM_ZONES 4

/* ------------------------------------------------------------------------- */
/* Carte des registres (holding registers, adressage 0-based)                 */
/* ------------------------------------------------------------------------- */
enum {
    REG_TEMP_ZONE1 = 0,
    REG_TEMP_ZONE2 = 1,
    REG_TEMP_ZONE3 = 2,
    REG_TEMP_ZONE4 = 3,
    REG_PYROMETER = 4,
    REG_QUENCH_PRESSURE = 5,
    REG_CONVEYOR_SPEED = 6,
    REG_BLOWER_CURRENT = 7,
    REG_POWER_KW = 8,
    REG_STATUS = 9,
    REG_SEQUENCE = 10,
    REG_SETPOINT_ZONE1 = 20,
    REG_SETPOINT_ZONE2 = 21,
    REG_SETPOINT_CONVEYOR = 22,
    REG_COMMAND = 30,
    REG_COUNT = 32
};

/* Registres inscriptibles par un client autorisé (salle de contrôle). */
#define REG_FIRST_WRITABLE REG_SETPOINT_ZONE1
#define REG_LAST_WRITABLE REG_COMMAND

/* Bits du registre d'état. */
enum {
    STATUS_RUNNING = 1u << 0,
    STATUS_EMERGENCY_STOP = 1u << 1,
    STATUS_MAINTENANCE_LOCK = 1u << 2
};

/* Commandes acceptées sur REG_COMMAND. */
enum {
    CMD_NONE = 0,
    CMD_EMERGENCY_STOP = 1,
    CMD_RESET = 2,
    CMD_ENTER_MAINTENANCE = 3,
    CMD_LEAVE_MAINTENANCE = 4
};

/* Codes d'exception Modbus. */
enum {
    MB_EXC_NONE = 0,
    MB_EXC_ILLEGAL_FUNCTION = 1,
    MB_EXC_ILLEGAL_DATA_ADDRESS = 2,
    MB_EXC_ILLEGAL_DATA_VALUE = 3,
    MB_EXC_SERVER_FAILURE = 4,
    MB_EXC_GATEWAY_TARGET_FAILED = 11
};

/* Plages physiques (unités scalées x10 ou x100 pour rester en entiers). */
#define TEMP_MIN_X10 0u
#define TEMP_MAX_X10 8500u
#define CONVEYOR_MIN_X100 0u
#define CONVEYOR_MAX_X100 5000u
#define QUENCH_MIN_X100 0u
#define QUENCH_MAX_X100 1200u

struct plant_state {
    uint16_t regs[REG_COUNT];
    uint32_t rng_state;
    uint32_t tick_count;
    uint8_t unit_id;
};

struct modbus_request {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t unit_id;
    uint8_t function_code;
    const uint8_t *pdu_data;
    size_t pdu_len;
};

/* --- plant.c -------------------------------------------------------------- */
void plant_init(struct plant_state *plant, uint8_t unit_id, uint32_t seed);
void plant_step(struct plant_state *plant);
uint16_t plant_read_register(const struct plant_state *plant, uint16_t address);
/*
 * Retourne MB_EXC_NONE en cas de succès, sinon un code d'exception Modbus.
 * `address` est relatif (0-based) et validé à l'intérieur de la fonction.
 */
uint8_t plant_write_register(struct plant_state *plant, uint16_t address, uint16_t value);
bool plant_is_emergency_stopped(const struct plant_state *plant);

/* --- modbus.c ------------------------------------------------------------- */
/*
 * Décode un ADU Modbus TCP. Retourne 0 si l'ADU est valide, -1 sinon.
 * Aucune allocation : `request` pointe à l'intérieur de `adu`.
 */
int modbus_parse_adu(const uint8_t *adu, size_t adu_len, struct modbus_request *request);

/*
 * Construit la réponse dans `out` (capacité `out_cap`).
 * Retourne le nombre d'octets écrits, ou -1 si la réponse ne tient pas.
 */
int modbus_build_response(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    struct plant_state *plant
);

/* Remplit un ADU d'exception (function_code | 0x80). */
int modbus_build_exception(
    uint8_t *out,
    size_t out_cap,
    const struct modbus_request *request,
    uint8_t function_code,
    uint8_t exception_code
);

#endif /* SECURIGLASS_PLC_H */
