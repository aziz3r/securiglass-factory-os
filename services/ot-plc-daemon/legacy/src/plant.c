/*
 * SecuriGlass Factory OS - Simulation du procédé (four de trempe + trempe).
 *
 * Toute l'arithmétique est entière (unités scalées) afin d'être :
 *  - déterministe et reproductible pour les tests ;
 *  - exempte de comportement indéfini (pas de conversion flottante, pas de
 *    dépassement signé) ;
 *  - bornée : chaque registre est maintenu dans sa plage physique.
 */

#include "securiglass_plc.h"

#include <string.h>

/* Générateur pseudo-aléatoire xorshift32 : rapide, sans allocation, déterministe. */
static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint16_t clamp_u16(uint32_t value, uint16_t low, uint16_t high)
{
    if (value < (uint32_t)low) {
        return low;
    }
    if (value > (uint32_t)high) {
        return high;
    }
    return (uint16_t)value;
}

void plant_init(struct plant_state *plant, uint8_t unit_id, uint32_t seed)
{
    if (plant == NULL) {
        return;
    }
    memset(plant, 0, sizeof(*plant));
    plant->rng_state = (seed != 0u) ? seed : 0x5EC0A0D1u;
    plant->unit_id = unit_id;

    plant->regs[REG_TEMP_ZONE1] = 7000u; /* 700.0 C */
    plant->regs[REG_TEMP_ZONE2] = 7040u;
    plant->regs[REG_TEMP_ZONE3] = 6980u;
    plant->regs[REG_TEMP_ZONE4] = 7020u;
    plant->regs[REG_SETPOINT_ZONE1] = 7000u;
    plant->regs[REG_SETPOINT_ZONE2] = 7000u;
    plant->regs[REG_SETPOINT_CONVEYOR] = 1200u; /* 12.00 m/min */
    plant->regs[REG_QUENCH_PRESSURE] = 550u;    /* 5.50 bar */
    plant->regs[REG_CONVEYOR_SPEED] = 1200u;
    plant->regs[REG_STATUS] = STATUS_RUNNING;
    plant->regs[REG_SEQUENCE] = 0u;
    plant->regs[REG_COMMAND] = CMD_NONE;
}

bool plant_is_emergency_stopped(const struct plant_state *plant)
{
    if (plant == NULL) {
        return true; /* fail-safe : sans état, on considère l'arrêt d'urgence */
    }
    return (plant->regs[REG_STATUS] & STATUS_EMERGENCY_STOP) != 0u;
}

static uint16_t simulated_temperature(uint32_t base, uint32_t setpoint, uint32_t *rng)
{
    /* Convergence douce vers la consigne + bruit de mesure borne. */
    uint32_t delta;
    uint32_t noise = xorshift32(rng) % 7u; /* 0..6 dixiemes */

    if (base < setpoint) {
        delta = setpoint - base;
        if (delta > 40u) {
            delta = 40u;
        }
        base += delta / 4u;
    } else if (base > setpoint) {
        delta = base - setpoint;
        if (delta > 40u) {
            delta = 40u;
        }
        base -= delta / 4u;
    }

    if ((xorshift32(rng) & 1u) != 0u) {
        base += noise;
    } else if (base > noise) {
        base -= noise;
    }
    return clamp_u16(base, TEMP_MIN_X10, TEMP_MAX_X10);
}

void plant_step(struct plant_state *plant)
{
    uint32_t setpoint_zone1;
    uint32_t setpoint_zone2;
    uint32_t average;
    uint32_t rng;

    if (plant == NULL) {
        return;
    }

    plant->tick_count++;
    rng = plant->rng_state;

    if (plant_is_emergency_stopped(plant)) {
        /* Arrêt d'urgence : refroidissement lent, aucune production. */
        uint32_t zone;
        for (zone = 0u; zone < PLANT_NUM_ZONES; zone++) {
            uint16_t current = plant->regs[REG_TEMP_ZONE1 + zone];
            plant->regs[REG_TEMP_ZONE1 + zone] =
                (current > 25u) ? (uint16_t)(current - 25u) : 0u;
        }
        plant->regs[REG_CONVEYOR_SPEED] = 0u;
        plant->regs[REG_QUENCH_PRESSURE] = 0u;
        plant->regs[REG_BLOWER_CURRENT] = 0u;
        plant->regs[REG_POWER_KW] = 12u;
    } else if ((plant->regs[REG_STATUS] & STATUS_MAINTENANCE_LOCK) != 0u) {
        /* Maintenance : procédé figé, pas de consigne appliquée. */
        plant->regs[REG_BLOWER_CURRENT] = 0u;
        plant->regs[REG_POWER_KW] = 8u;
    } else {
        setpoint_zone1 = plant->regs[REG_SETPOINT_ZONE1];
        setpoint_zone2 = plant->regs[REG_SETPOINT_ZONE2];

        plant->regs[REG_TEMP_ZONE1] = simulated_temperature(
            plant->regs[REG_TEMP_ZONE1], setpoint_zone1, &rng);
        plant->regs[REG_TEMP_ZONE2] = simulated_temperature(
            plant->regs[REG_TEMP_ZONE2], setpoint_zone2, &rng);
        plant->regs[REG_TEMP_ZONE3] = simulated_temperature(
            plant->regs[REG_TEMP_ZONE3], setpoint_zone1, &rng);
        plant->regs[REG_TEMP_ZONE4] = simulated_temperature(
            plant->regs[REG_TEMP_ZONE4], setpoint_zone2, &rng);

        average = (uint32_t)plant->regs[REG_TEMP_ZONE1] +
                  (uint32_t)plant->regs[REG_TEMP_ZONE2] +
                  (uint32_t)plant->regs[REG_TEMP_ZONE3] +
                  (uint32_t)plant->regs[REG_TEMP_ZONE4];
        plant->regs[REG_PYROMETER] = (uint16_t)(average / PLANT_NUM_ZONES);

        plant->regs[REG_CONVEYOR_SPEED] = plant->regs[REG_SETPOINT_CONVEYOR];
        plant->regs[REG_QUENCH_PRESSURE] =
            clamp_u16(545u + (xorshift32(&rng) % 12u), QUENCH_MIN_X100, QUENCH_MAX_X100);
        plant->regs[REG_BLOWER_CURRENT] =
            clamp_u16(380u + (average / 240u) + (xorshift32(&rng) % 16u), 0u, 600u);
        plant->regs[REG_POWER_KW] =
            clamp_u16(12000u + (average / 6u) + (xorshift32(&rng) % 400u), 0u, 25000u);
    }

    plant->rng_state = rng;
    plant->regs[REG_SEQUENCE] = (uint16_t)(plant->tick_count & 0xFFFFu);
}

uint16_t plant_read_register(const struct plant_state *plant, uint16_t address)
{
    if (plant == NULL || address >= REG_COUNT) {
        return 0u;
    }
    return plant->regs[address];
}

uint8_t plant_write_register(struct plant_state *plant, uint16_t address, uint16_t value)
{
    if (plant == NULL) {
        return MB_EXC_SERVER_FAILURE;
    }
    if (address < REG_FIRST_WRITABLE || address > REG_LAST_WRITABLE || address >= REG_COUNT) {
        return MB_EXC_ILLEGAL_DATA_ADDRESS;
    }

    /* Interlock : aucune consigne de procédé acceptée en arrêt d'urgence. */
    if (plant_is_emergency_stopped(plant) && address != REG_COMMAND) {
        return MB_EXC_SERVER_FAILURE;
    }

    switch (address) {
    case REG_SETPOINT_ZONE1:
    case REG_SETPOINT_ZONE2:
        if (value > TEMP_MAX_X10) {
            return MB_EXC_ILLEGAL_DATA_VALUE;
        }
        break;
    case REG_SETPOINT_CONVEYOR:
        if (value > CONVEYOR_MAX_X100) {
            return MB_EXC_ILLEGAL_DATA_VALUE;
        }
        break;
    case REG_COMMAND:
        switch (value) {
        case CMD_EMERGENCY_STOP:
            plant->regs[REG_STATUS] |= STATUS_EMERGENCY_STOP;
            break;
        case CMD_RESET:
            /* Un reset n'est accepté que si le procédé est en sécurité. */
            if (!plant_is_emergency_stopped(plant)) {
                return MB_EXC_ILLEGAL_DATA_VALUE;
            }
            plant->regs[REG_STATUS] = STATUS_RUNNING;
            break;
        case CMD_ENTER_MAINTENANCE:
            plant->regs[REG_STATUS] |= STATUS_MAINTENANCE_LOCK;
            break;
        case CMD_LEAVE_MAINTENANCE:
            plant->regs[REG_STATUS] &= (uint16_t)~STATUS_MAINTENANCE_LOCK;
            break;
        default:
            return MB_EXC_ILLEGAL_DATA_VALUE;
        }
        return MB_EXC_NONE;
    default:
        return MB_EXC_ILLEGAL_DATA_ADDRESS;
    }

    plant->regs[address] = value;
    return MB_EXC_NONE;
}
