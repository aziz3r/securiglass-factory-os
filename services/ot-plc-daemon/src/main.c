/**
 * @file main.c
 * @brief Point d'entrée principal du Démon Automate PLC SecuriGlass (Niveau 1 OT)
 *
 * Architecture :
 * - Processus unique, mémoire pré-allouée, zéro allocation dynamique résiduelle.
 * - Serveur Modbus TCP écoutant sur le port 5020.
 * - Boucle temps réel cadencée à 100ms exécutant la thermodynamique du four (EN 12150).
 * - Sortie propre et libération de toutes les ressources sur SIGINT/SIGTERM.
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_modbus.h"
#include "plc_simulator.h"
#include "plc_types.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n"
           "Démon Automate PLC SecuriGlass (Simulateur Four de Trempe EN 12150)\n\n"
           "Options:\n"
           "  -b, --bind IP        Adresse IP d'écoute Modbus TCP (défaut: 127.0.0.1)\n"
           "  -p, --port PORT      Port d'écoute Modbus TCP (défaut: 5020)\n"
           "  -t, --test-mode      Activer le mode test (durée limitée pour CI / Valgrind)\n"
           "  -d, --duration SEC   Durée d'exécution en secondes en mode test (défaut: 5)\n"
           "  -v, --verbose        Afficher les traces détaillées de l'automate\n"
           "  -h, --help           Afficher cette aide\n", prog_name);
}

int main(int argc, char **argv)
{
    const char *bind_ip = "127.0.0.1";
    int port = 5020;
    bool test_mode = false;
    int duration_seconds = 5;
    bool verbose = false;

    static struct option long_options[] = {
        {"bind",      required_argument, NULL, 'b'},
        {"port",      required_argument, NULL, 'p'},
        {"test-mode", no_argument,       NULL, 't'},
        {"duration",  required_argument, NULL, 'd'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "b:p:td:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'b':
            bind_ip = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Erreur: Port invalide %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 't':
            test_mode = true;
            break;
        case 'd':
            duration_seconds = atoi(optarg);
            if (duration_seconds <= 0) {
                duration_seconds = 5;
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    plc_context_t ctx;
    plc_simulator_init(&ctx);

    if (verbose) {
        printf("[PLC] Démarrage du démon SecuriGlass PLC...\n");
        printf("[PLC] Écoute Modbus TCP sur %s:%d\n", bind_ip, port);
    }

    int rc = plc_modbus_server_start(&ctx, bind_ip, port);
    if (rc != 0) {
        fprintf(stderr, "[PLC-ERROR] Impossible de démarrer le serveur Modbus TCP (code: %d)\n", rc);
        plc_simulator_destroy(&ctx);
        return EXIT_FAILURE;
    }

    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 100000000L; /* 100 ms = 0.1s */

    time_t start_time = time(NULL);

    while (g_running) {
        plc_simulator_step(&ctx, 0.10);

        if (test_mode) {
            if (difftime(time(NULL), start_time) >= (double)duration_seconds) {
                if (verbose) {
                    printf("[PLC] Fin du test temporisé (%d s).\n", duration_seconds);
                }
                break;
            }
        }

        nanosleep(&sleep_time, NULL);
    }

    if (verbose) {
        printf("[PLC] Arrêt du serveur Modbus TCP...\n");
    }
    plc_modbus_server_stop();

    plc_simulator_destroy(&ctx);

    if (verbose) {
        printf("[PLC] Démon arrêté proprement. Zéro fuite mémoire.\n");
    }

    return EXIT_SUCCESS;
}
