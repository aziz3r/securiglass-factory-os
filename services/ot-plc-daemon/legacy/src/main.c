/*
 * SecuriGlass Factory OS - Démon PLC Modbus TCP (Purdue 1/2).
 *
 * Boucle d'événements unique (poll) : pas de thread, pas de verrou, pas de
 * course de données. Aucune allocation dynamique : la mémoire est entièrement
 * statique, ce qui rend les fuites structurellement impossibles et vérifiable
 * sous Valgrind (0 octet perdu, 0 erreur).
 *
 * Usage :
 *   ot-plc-daemon [--bind 127.0.0.1] [--port 5020] [--unit 1]
 *                 [--seed N] [--tick-ms 500] [--verbose]
 */

#define _POSIX_C_SOURCE 200809L

#include "securiglass_plc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__GNUC__)
#define SECURIGLASS_NODISCARD __attribute__((warn_unused_result))
#else
#define SECURIGLASS_NODISCARD
#endif

struct client_slot {
    int fd;
    size_t rx_len;
    uint8_t rx_buf[MB_MAX_ADU * 2u];
};

static volatile sig_atomic_t g_running = 1;
static struct client_slot g_clients[MAX_CLIENTS];
static int g_verbose = 0;

static void handle_signal(int signum)
{
    (void)signum;
    g_running = 0;
}

static void log_message(const char *level, const char *message)
{
    if (!g_verbose && strcmp(level, "ERROR") != 0) {
        return;
    }
    fprintf(stderr, "[%s] %s\n", level, message);
    fflush(stderr);
}

static void log_errno(const char *context)
{
    fprintf(stderr, "[ERROR] %s : %s\n", context, strerror(errno));
    fflush(stderr);
}

static SECURIGLASS_NODISCARD int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static SECURIGLASS_NODISCARD int send_all(int fd, const uint8_t *buffer, size_t length)
{
    size_t sent = 0u;

    while (sent < length) {
        ssize_t written = send(fd, buffer + sent, length - sent, MSG_NOSIGNAL);
        if (written > 0) {
            sent += (size_t)written;
            continue;
        }
        if (written < 0 && (errno == EINTR)) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return -1; /* client trop lent : on ferme plutôt que de bloquer l'automate */
        }
        return -1;
    }
    return 0;
}

static void close_client(struct client_slot *slot)
{
    if (slot->fd >= 0) {
        close(slot->fd);
        slot->fd = -1;
    }
    slot->rx_len = 0u;
}

static void accept_clients(int listen_fd)
{
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        size_t i;

        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return;
            }
            log_errno("accept");
            return;
        }
        if (set_nonblocking(fd) != 0) {
            log_errno("set_nonblocking(client)");
            close(fd);
            continue;
        }
        for (i = 0u; i < MAX_CLIENTS; i++) {
            if (g_clients[i].fd < 0) {
                g_clients[i].fd = fd;
                g_clients[i].rx_len = 0u;
                log_message("INFO", "nouveau client Modbus connecté");
                break;
            }
        }
        if (i == MAX_CLIENTS) {
            log_message("ERROR", "saturation : connexion Modbus refusée (limite 16)");
            close(fd);
        }
    }
}

/*
 * Traite tout ADU complet présent dans le tampon du client.
 * Retourne 0 pour continuer, -1 si le client doit être fermé.
 */
static int process_buffered_frames(struct client_slot *slot, struct plant_state *plant)
{
    while (slot->rx_len >= MBAP_HEADER_LEN) {
        uint16_t length_field = (uint16_t)(((uint16_t)slot->rx_buf[4] << 8) | slot->rx_buf[5]);
        size_t frame_len;
        struct modbus_request request;
        uint8_t response[MB_MAX_ADU];
        int response_len;

        if (length_field < 2u || length_field > MB_MAX_PDU) {
            log_message("ERROR", "trame Modbus invalide : champ longueur hors bornes");
            return -1;
        }
        frame_len = 6u + (size_t)length_field;
        if (frame_len > sizeof(slot->rx_buf)) {
            log_message("ERROR", "trame Modbus invalide : longueur excessive");
            return -1;
        }
        if (slot->rx_len < frame_len) {
            return 0; /* attendre la suite */
        }

        if (modbus_parse_adu(slot->rx_buf, frame_len, &request) != 0) {
            log_message("ERROR", "ADU Modbus rejeté (en-tête incohérent)");
            return -1;
        }

        response_len = modbus_build_response(response, sizeof(response), &request, plant);
        if (response_len < 0) {
            log_message("ERROR", "échec de construction de la réponse Modbus");
            return -1;
        }
        if (send_all(slot->fd, response, (size_t)response_len) != 0) {
            return -1;
        }

        /* Consommer la trame et compacter le reste (borné : <= 2 ADU). */
        slot->rx_len -= frame_len;
        if (slot->rx_len > 0u) {
            memmove(slot->rx_buf, slot->rx_buf + frame_len, slot->rx_len);
        }
    }
    return 0;
}

static int read_from_client(struct client_slot *slot, struct plant_state *plant)
{
    ssize_t received;
    size_t room = sizeof(slot->rx_buf) - slot->rx_len;

    if (room == 0u) {
        log_message("ERROR", "tampon client plein : fermeture");
        return -1;
    }
    received = recv(slot->fd, slot->rx_buf + slot->rx_len, room, 0);
    if (received == 0) {
        return -1; /* connexion fermée par le pair */
    }
    if (received < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    slot->rx_len += (size_t)received;
    return process_buffered_frames(slot, plant);
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--bind ADDR] [--port PORT] [--unit ID] [--seed N]"
            " [--tick-ms MS] [--verbose]\n",
            program);
}

static int parse_u32(const char *raw, uint32_t min, uint32_t max, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (raw == NULL || out == NULL) {
        return -1;
    }
    errno = 0;
    value = strtoul(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0' || value < min || value > max) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    const char *bind_address = "127.0.0.1";
    uint32_t port = 5020u;
    uint32_t unit = 1u;
    uint32_t seed = 0u;
    uint32_t tick_ms = 500u;
    struct plant_state plant;
    struct sockaddr_in address;
    struct pollfd poll_fds[MAX_CLIENTS + 1];
    int listen_fd = -1;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_address = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 1u, 65535u, &port) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--unit") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 1u, 247u, &unit) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 1u, UINT32_MAX, &seed) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--tick-ms") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 10u, 60000u, &tick_ms) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    for (i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].fd = -1;
        g_clients[i].rx_len = 0u;
    }
    plant_init(&plant, (uint8_t)unit, seed);

    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_signal;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
            log_errno("sigaction");
            return 1;
        }
        signal(SIGPIPE, SIG_IGN);
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_errno("socket");
        return 1;
    }
    {
        int reuse = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
            log_errno("setsockopt(SO_REUSEADDR)");
            close(listen_fd);
            return 1;
        }
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_address, &address.sin_addr) != 1) {
        fprintf(stderr, "[ERROR] adresse de bind invalide : %s\n", bind_address);
        close(listen_fd);
        return 2;
    }
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        log_errno("bind");
        close(listen_fd);
        return 1;
    }
    if (listen(listen_fd, 8) != 0) {
        log_errno("listen");
        close(listen_fd);
        return 1;
    }
    if (set_nonblocking(listen_fd) != 0) {
        log_errno("set_nonblocking(listen)");
        close(listen_fd);
        return 1;
    }

    fprintf(stderr,
            "[INFO] ot-plc-daemon à l'écoute sur %s:%u (unit=%u, tick=%ums, seed=%u)\n",
            bind_address,
            port,
            unit,
            tick_ms,
            seed);
    fflush(stderr);

    while (g_running) {
        int ready;
        int poll_count = 0;

        poll_fds[poll_count].fd = listen_fd;
        poll_fds[poll_count].events = POLLIN;
        poll_fds[poll_count].revents = 0;
        poll_count++;

        for (i = 0; i < MAX_CLIENTS; i++) {
            if (g_clients[i].fd >= 0) {
                poll_fds[poll_count].fd = g_clients[i].fd;
                poll_fds[poll_count].events = POLLIN;
                poll_fds[poll_count].revents = 0;
                poll_count++;
            }
        }

        ready = poll(poll_fds, (nfds_t)poll_count, (int)tick_ms);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_errno("poll");
            break;
        }

        /* Le temps avance même sans trafic : le four continue de simuler. */
        plant_step(&plant);

        if (ready > 0 && (poll_fds[0].revents & POLLIN) != 0) {
            accept_clients(listen_fd);
        }

        if (ready > 0) {
            size_t index = 1u;
            for (i = 0; i < MAX_CLIENTS; i++) {
                short revents;

                if (g_clients[i].fd < 0) {
                    continue;
                }
                revents = poll_fds[index].revents;
                index++;
                if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    close_client(&g_clients[i]);
                    continue;
                }
                if ((revents & POLLIN) != 0 && read_from_client(&g_clients[i], &plant) != 0) {
                    close_client(&g_clients[i]);
                }
            }
        }
    }

    fprintf(stderr, "[INFO] arrêt demandé : fermeture propre\n");
    for (i = 0; i < MAX_CLIENTS; i++) {
        close_client(&g_clients[i]);
    }
    close(listen_fd);
    return 0;
}
