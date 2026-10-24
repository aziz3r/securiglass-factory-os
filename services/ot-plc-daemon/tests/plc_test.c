/**
 * @file plc_test.c
 * @brief Tests unitaires du démon PLC : simulateur physique, Modbus TCP, E-STOP
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_modbus.h"
#include "plc_simulator.h"
#include "plc_types.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        g_tests_run++; \
        if (cond) { \
            g_tests_passed++; \
        } else { \
            fprintf(stderr, "[FAIL] %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #cond); \
        } \
    } while (0)

static void test_simulator_init(void)
{
    plc_context_t ctx;
    plc_simulator_init(&ctx);

    TEST_ASSERT(ctx.state == CYCLE_STATE_IDLE, "State initial doit être IDLE");
    TEST_ASSERT(ctx.metrics.temp_zone1 == 25.0, "T° Zone 1 ambiante initiale");
    TEST_ASSERT(ctx.setpoints.setpoint_temp_z1 == 700.0, "Consigne T° Zone 1 à 700.0 °C");
    TEST_ASSERT(!ctx.emergency_stop, "E-STOP initialement inactif");
    TEST_ASSERT(ctx.door_interlock, "Sas initialement fermé");

    plc_simulator_destroy(&ctx);
}

static void test_simulator_heating_step(void)
{
    plc_context_t ctx;
    plc_simulator_init(&ctx);

    /* Démarre le cycle */
    pthread_mutex_lock(&ctx.lock);
    bool accepted = plc_apply_command(&ctx, PLC_CMD_START_CYCLE);
    pthread_mutex_unlock(&ctx.lock);
    TEST_ASSERT(accepted, "Ordre START_CYCLE accepté");

    /* Simule 5 secondes */
    for (int i = 0; i < 50; i++) {
        plc_simulator_step(&ctx, 0.10);
    }

    pthread_mutex_lock(&ctx.lock);
    TEST_ASSERT(ctx.metrics.temp_zone1 > 25.0, "T° Zone 1 a chauffé");
    TEST_ASSERT(ctx.status_flags & PLC_FLAG_HEATERS_ON, "Drapeau HEATERS_ON actif");
    pthread_mutex_unlock(&ctx.lock);

    plc_simulator_destroy(&ctx);
}

static void test_emergency_stop_trip_and_reset(void)
{
    plc_context_t ctx;
    plc_simulator_init(&ctx);

    /* Déclenche l'E-STOP */
    pthread_mutex_lock(&ctx.lock);
    plc_trigger_estop(&ctx);
    TEST_ASSERT(ctx.emergency_stop, "E-STOP activé");
    TEST_ASSERT(ctx.state == CYCLE_STATE_E_STOP, "État passé à CYCLE_STATE_E_STOP");
    TEST_ASSERT(ctx.status_flags & PLC_FLAG_E_STOP_ACTIVE, "Drapeau E-STOP_ACTIVE présent");

    /* Tente de réarmer avec bouton encore appuyé (échec attendu) */
    bool reset_ok = plc_reset_estop(&ctx);
    TEST_ASSERT(!reset_ok, "Réarmement impossible si E-STOP maintenu");

    /* Libère le bouton physique et réarme */
    ctx.emergency_stop = false;
    reset_ok = plc_reset_estop(&ctx);
    TEST_ASSERT(reset_ok, "Réarmement réussi");
    TEST_ASSERT(ctx.state == CYCLE_STATE_IDLE, "Retour à IDLE");
    pthread_mutex_unlock(&ctx.lock);

    plc_simulator_destroy(&ctx);
}

static void test_modbus_frame_processing(void)
{
    plc_context_t ctx;
    plc_simulator_init(&ctx);

    /* Requête Modbus Read Input Registers (FC 0x04) pour les 12 registres process */
    uint8_t req[12] = {
        0x00, 0x01, /* Transaction ID: 1 */
        0x00, 0x00, /* Protocol ID: 0 */
        0x00, 0x06, /* Length: 6 */
        0x01,       /* Unit ID: 1 */
        0x04,       /* Function Code: 0x04 Read Input Registers */
        0x00, 0x00, /* Start Address: 0 */
        0x00, 0x0C  /* Register Count: 12 */
    };

    uint8_t resp[260];
    int resp_len = plc_modbus_process_frame(&ctx, req, sizeof(req), resp, sizeof(resp));

    TEST_ASSERT(resp_len == (7 + 2 + 24), "Taille réponse Modbus FC 0x04 correcte (33 octets)");
    TEST_ASSERT(resp[7] == 0x04, "FC écho dans la réponse");
    TEST_ASSERT(resp[8] == 24, "Byte count = 24 octets (12 registres)");

    /* Requête Modbus Discrete Inputs (FC 0x02) */
    uint8_t req_di[12] = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01,
        0x02,       /* FC 0x02 Read Discrete Inputs */
        0x00, 0x00, 0x00, 0x04
    };
    resp_len = plc_modbus_process_frame(&ctx, req_di, sizeof(req_di), resp, sizeof(resp));
    TEST_ASSERT(resp_len == (7 + 2 + 1), "Taille réponse Discrete Inputs correcte (10 octets)");
    TEST_ASSERT(resp[7] == 0x02, "FC écho pour Discrete Inputs");

    /* Requête Fonction Invalide (FC 0x2A) -> Exception 0x01 attendue */
    uint8_t req_bad[8] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01,
        0x2A
    };
    resp_len = plc_modbus_process_frame(&ctx, req_bad, sizeof(req_bad), resp, sizeof(resp));
    TEST_ASSERT(resp_len == 9, "Taille réponse exception correcte");
    TEST_ASSERT(resp[7] == (0x2A | 0x80), "FC d'erreur avec bit 7 activé");
    TEST_ASSERT(resp[8] == 0x01, "Exception code 0x01 (Illegal Function)");

    plc_simulator_destroy(&ctx);
}

int main(void)
{
    printf("=== Démarrage des Tests Unitaires Automate C (SecuriGlass PLC) ===\n");

    test_simulator_init();
    test_simulator_heating_step();
    test_emergency_stop_trip_and_reset();
    test_modbus_frame_processing();

    printf("=== Bilan Tests PLC: %d/%d passés avec succès ===\n", g_tests_passed, g_tests_run);

    if (g_tests_passed == g_tests_run) {
        printf("[SUCCESS] Tous les tests C du démon PLC ont réussi.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "[FAILURE] Échec de certains tests C.\n");
        return EXIT_FAILURE;
    }
}
