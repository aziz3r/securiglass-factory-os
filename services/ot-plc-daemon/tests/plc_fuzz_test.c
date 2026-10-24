/**
 * @file plc_fuzz_test.c
 * @brief Suite de Fuzzing intensif et de tests de robustesse Modbus TCP en C
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_modbus.h"
#include "plc_simulator.h"
#include "plc_types.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_fuzz_runs = 0;
static int g_fuzz_passed = 0;

#define FUZZ_CHECK(cond, msg) \
    do { \
        g_fuzz_runs++; \
        if (cond) { \
            g_fuzz_passed++; \
        } else { \
            fprintf(stderr, "[FUZZ-FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
        } \
    } while (0)

static void test_fuzz_all_function_codes(plc_context_t *ctx)
{
    uint8_t resp[300];
    for (int fc = 0; fc <= 255; fc++) {
        uint8_t req[12] = {
            0x00, 0x01, /* Tx ID */
            0x00, 0x00, /* Proto ID */
            0x00, 0x06, /* Len */
            0x01,       /* Unit ID */
            (uint8_t)fc,
            0x00, 0x00, 0x00, 0x01
        };

        int resp_len = plc_modbus_process_frame(ctx, req, sizeof(req), resp, sizeof(resp));
        if (fc == 0x01 || fc == 0x02 || fc == 0x03 || fc == 0x04 || fc == 0x05 || fc == 0x06 || fc == 0x10) {
            FUZZ_CHECK(resp_len > 0, "Fonction Modbus valide doit recevoir une réponse ou exception");
        } else {
            FUZZ_CHECK(resp_len == 9, "Fonction illégale doit renvoyer une réponse d'exception de 9 octets");
            if (resp_len == 9) {
                FUZZ_CHECK(resp[7] == (fc | 0x80), "Bit d'exception activé");
                FUZZ_CHECK(resp[8] == 0x01, "Exception code 0x01 (Illegal Function)");
            }
        }
    }
}

static void test_fuzz_truncated_frames(plc_context_t *ctx)
{
    uint8_t resp[300];
    uint8_t sample[12] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x04 };

    for (size_t len = 0; len < 7; len++) {
        int resp_len = plc_modbus_process_frame(ctx, sample, len, resp, sizeof(resp));
        FUZZ_CHECK(resp_len <= 0, "Trame tronquée (< 7 octets MBAP) doit être rejetée sans réponse");
    }
}

static void test_fuzz_protocol_id_tamper(plc_context_t *ctx)
{
    uint8_t resp[300];
    uint8_t req[12] = {
        0x00, 0x01,
        0x12, 0x34, /* Protocol ID != 0 (interdit en Modbus TCP) */
        0x00, 0x06,
        0x01,
        0x04, 0x00, 0x00, 0x00, 0x04
    };

    int resp_len = plc_modbus_process_frame(ctx, req, sizeof(req), resp, sizeof(resp));
    FUZZ_CHECK(resp_len <= 0, "Protocol ID != 0 doit être ignoré/rejeté");
}

static void test_fuzz_massive_random_payloads(plc_context_t *ctx)
{
    uint8_t req[512];
    uint8_t resp[512];
    srand(1337);

    for (int iter = 0; iter < 10000; iter++) {
        size_t len = (size_t)(rand() % 400 + 1);
        for (size_t i = 0; i < len; i++) {
            req[i] = (uint8_t)(rand() & 0xFF);
        }

        /* Aucun crash toléré */
        int resp_len = plc_modbus_process_frame(ctx, req, len, resp, sizeof(resp));
        (void)resp_len;
    }
    FUZZ_CHECK(1, "10 000 trames aléatoires traitées sans aucun crash (SIGSEGV/SIGABRT)");
}

int main(void)
{
    printf("=== Démarrage du Fuzzing Intensif Modbus C (SecuriGlass Red Team) ===\n");

    plc_context_t ctx;
    plc_simulator_init(&ctx);

    test_fuzz_all_function_codes(&ctx);
    test_fuzz_truncated_frames(&ctx);
    test_fuzz_protocol_id_tamper(&ctx);
    test_fuzz_massive_random_payloads(&ctx);

    plc_simulator_destroy(&ctx);

    printf("=== Bilan Fuzzing Modbus: %d/%d tests passés avec succès ===\n", g_fuzz_passed, g_fuzz_runs);

    if (g_fuzz_passed == g_fuzz_runs) {
        printf("[SUCCESS] Résilience totale du moteur Modbus C aux attaques de fuzzing.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "[FAILURE] Vulnérabilité ou anomalie détectée pendant le fuzzing.\n");
        return EXIT_FAILURE;
    }
}
