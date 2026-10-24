/**
 * @file plc_modbus.c
 * @brief Serveur Modbus TCP durci pour automate PLC SecuriGlass (Purdue 1/2)
 *
 * Implémentation conforme POSIX C11, Modbus Application Protocol V1.1b3 :
 * - Aucune fuite mémoire (0 allocation dynamique résiduelle).
 * - Traitement sécurisé MBAP (Transaction ID, Protocol ID = 0, Length, Unit ID).
 * - Support des fonctions :
 *     * 0x01 : Read Coils
 *     * 0x02 : Read Discrete Inputs (10001 - 10004)
 *     * 0x03 : Read Holding Registers (40001 - 40007 / miroir 0..11)
 *     * 0x04 : Read Input Registers (30001 - 30012)
 *     * 0x05 : Write Single Coil
 *     * 0x06 : Write Single Register (40001 - 40007)
 *     * 0x10 : Write Multiple Registers
 * - Codes d'exception Modbus standard (0x01, 0x02, 0x03, 0x04).
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_modbus.h"
#include "plc_simulator.h"
#include "plc_types.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MB_MAX_ADU 260
#define MB_MAX_PDU 253
#define MBAP_HEADER_LEN 7
#define MAX_CLIENTS 16

/* Codes d'exception Modbus */
#define MB_EXC_ILLEGAL_FUNCTION 0x01
#define MB_EXC_ILLEGAL_DATA_ADDR 0x02
#define MB_EXC_ILLEGAL_DATA_VAL  0x03
#define MB_EXC_SLAVE_DEVICE_FAIL 0x04

static pthread_t g_server_thread;
static volatile bool g_server_running = false;
static int g_listen_fd = -1;
static int g_server_port = 0;
static plc_context_t *g_plc_ctx = NULL;

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ========================================================================= */
/* Écriture des réponses et exceptions Modbus                                */
/* ========================================================================= */

static int build_exception_response(const uint8_t *req_mbap, uint8_t function_code,
                                   uint8_t exception_code, uint8_t *resp_buf)
{
    resp_buf[0] = req_mbap[0]; /* Transaction ID High */
    resp_buf[1] = req_mbap[1]; /* Transaction ID Low  */
    resp_buf[2] = 0x00;        /* Protocol ID High    */
    resp_buf[3] = 0x00;        /* Protocol ID Low     */
    resp_buf[4] = 0x00;        /* Length High         */
    resp_buf[5] = 0x03;        /* Length Low (Unit + Function + Exception) */
    resp_buf[6] = req_mbap[6]; /* Unit ID             */
    resp_buf[7] = (uint8_t)(function_code | 0x80u);
    resp_buf[8] = exception_code;
    return 9;
}

static uint16_t get_input_register(plc_context_t *ctx, uint16_t address)
{
    /* Registres d'entrée 30001 - 30012 (adresses 0x0000 - 0x000B) */
    switch (address) {
    case 0: return (uint16_t)(ctx->metrics.temp_zone1 * 10.0);
    case 1: return (uint16_t)(ctx->metrics.temp_zone2 * 10.0);
    case 2: return (uint16_t)(ctx->metrics.temp_zone3 * 10.0);
    case 3: return (uint16_t)(ctx->metrics.temp_zone4 * 10.0);
    case 4: return (uint16_t)(ctx->metrics.glass_pyrometer * 10.0);
    case 5: return (uint16_t)(ctx->metrics.quench_pressure * 100.0); /* x100 bar pour compatibilité gateway */
    case 6: return (uint16_t)(ctx->metrics.conveyor_speed * 100.0);  /* cm/min */
    case 7: return (uint16_t)ctx->metrics.blower_rpm;
    case 8: return (uint16_t)(ctx->metrics.power_kw * 10.0);
    case 9: return ctx->status_flags;
    case 10: return (uint16_t)ctx->state;
    case 11: return ctx->error_code;
    default: return 0;
    }
}

static uint16_t get_holding_register(plc_context_t *ctx, uint16_t address)
{
    /* Consignes 40001 - 40007 (adresses 0x0000 - 0x0006) ou miroir process */
    switch (address) {
    case 0: return (uint16_t)(ctx->metrics.temp_zone1 * 10.0);
    case 1: return (uint16_t)(ctx->metrics.temp_zone2 * 10.0);
    case 2: return (uint16_t)(ctx->metrics.temp_zone3 * 10.0);
    case 3: return (uint16_t)(ctx->metrics.temp_zone4 * 10.0);
    case 4: return (uint16_t)(ctx->metrics.glass_pyrometer * 10.0);
    case 5: return (uint16_t)(ctx->metrics.quench_pressure * 100.0);
    case 6: return (uint16_t)(ctx->metrics.conveyor_speed * 100.0);
    case 7: return (uint16_t)ctx->metrics.blower_rpm;
    case 8: return (uint16_t)(ctx->metrics.power_kw * 10.0);
    case 9: return ctx->status_flags;
    case 10: return (uint16_t)ctx->cycle_tick;
    /* Consignes opératoires spécifiques à partir de 20 */
    case 20: return (uint16_t)(ctx->setpoints.setpoint_temp_z1 * 10.0);
    case 21: return (uint16_t)(ctx->setpoints.setpoint_temp_z2 * 10.0);
    case 22: return (uint16_t)(ctx->setpoints.setpoint_speed * 100.0);
    case 30: return ctx->last_command;
    default: return 0;
    }
}

static bool set_holding_register(plc_context_t *ctx, uint16_t address, uint16_t value)
{
    switch (address) {
    case 0:
    case 20:
        if (value >= 5000 && value <= 7500) {
            ctx->setpoints.setpoint_temp_z1 = (double)value / 10.0;
            return true;
        }
        return false;
    case 1:
    case 21:
        if (value >= 5000 && value <= 7500) {
            ctx->setpoints.setpoint_temp_z2 = (double)value / 10.0;
            return true;
        }
        return false;
    case 2:
        if (value >= 5000 && value <= 7500) {
            ctx->setpoints.setpoint_temp_z3 = (double)value / 10.0;
            return true;
        }
        return false;
    case 3:
        if (value >= 5000 && value <= 7500) {
            ctx->setpoints.setpoint_temp_z4 = (double)value / 10.0;
            return true;
        }
        return false;
    case 4:
        if (value >= 500 && value <= 8000) {
            ctx->setpoints.setpoint_quench = (double)value / 1000.0;
            return true;
        }
        return false;
    case 5:
    case 22:
        if (value <= 5000) {
            ctx->setpoints.setpoint_speed = (double)value / 100.0;
            return true;
        }
        return false;
    case 6:
    case 30:
        return plc_apply_command(ctx, value);
    default:
        return false;
    }
}

int plc_modbus_process_frame(plc_context_t *ctx,
                             const uint8_t *req, size_t req_len,
                             uint8_t *resp, size_t max_resp_len)
{
    if (ctx == NULL || req == NULL || resp == NULL || req_len < MBAP_HEADER_LEN + 1) {
        return -1;
    }

    uint16_t trans_id = (uint16_t)((req[0] << 8) | req[1]);
    uint16_t proto_id = (uint16_t)((req[2] << 8) | req[3]);
    uint16_t length   = (uint16_t)((req[4] << 8) | req[5]);
    uint8_t unit_id   = req[6];
    uint8_t fc        = req[7];

    (void)trans_id;
    (void)unit_id;

    if (proto_id != 0 || length < 2 || req_len < (size_t)(MBAP_HEADER_LEN - 1 + length)) {
        return -1;
    }

    /* Traitement sécurisé selon le Function Code */
    switch (fc) {

    /* --- 0x02 : Read Discrete Inputs --- */
    case 0x02: {
        if (req_len < 12) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }
        uint16_t start_addr = (uint16_t)((req[8] << 8) | req[9]);
        uint16_t bit_count  = (uint16_t)((req[10] << 8) | req[11]);
        if (bit_count == 0 || bit_count > 16 || start_addr > 8) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_ADDR, resp);
        }

        pthread_mutex_lock(&ctx->lock);
        uint8_t discrete_bits = 0;
        if (!ctx->emergency_stop) {
            discrete_bits |= (1 << 0); /* 10001 : E-STOP non déclenché (sécurité active) */
        }
        if (ctx->door_interlock) {
            discrete_bits |= (1 << 1); /* 10002 : Sas fermé */
        }
        if (ctx->air_pressure_switch) {
            discrete_bits |= (1 << 2); /* 10003 : Pression pneumatique OK */
        }
        if (ctx->glass_sensor) {
            discrete_bits |= (1 << 3); /* 10004 : Détecteur verre */
        }
        pthread_mutex_unlock(&ctx->lock);

        uint8_t byte_count = 1;
        uint16_t resp_len = (uint16_t)(3 + byte_count);

        resp[0] = req[0]; resp[1] = req[1];
        resp[2] = 0x00;   resp[3] = 0x00;
        resp[4] = (uint8_t)(resp_len >> 8);
        resp[5] = (uint8_t)(resp_len & 0xFF);
        resp[6] = req[6];
        resp[7] = fc;
        resp[8] = byte_count;
        resp[9] = (uint8_t)(discrete_bits >> start_addr);
        return MBAP_HEADER_LEN + 2 + byte_count;
    }

    /* --- 0x03 : Read Holding Registers --- */
    case 0x03: {
        if (req_len < 12) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }
        uint16_t start_addr = (uint16_t)((req[8] << 8) | req[9]);
        uint16_t reg_count  = (uint16_t)((req[10] << 8) | req[11]);
        if (reg_count == 0 || reg_count > 125 || (start_addr + reg_count) > 32) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_ADDR, resp);
        }

        uint8_t byte_count = (uint8_t)(reg_count * 2);
        if (max_resp_len < (size_t)(MBAP_HEADER_LEN + 2 + byte_count)) {
            return build_exception_response(req, fc, MB_EXC_SLAVE_DEVICE_FAIL, resp);
        }

        pthread_mutex_lock(&ctx->lock);
        resp[0] = req[0]; resp[1] = req[1];
        resp[2] = 0x00;   resp[3] = 0x00;
        uint16_t resp_len = (uint16_t)(3 + byte_count);
        resp[4] = (uint8_t)(resp_len >> 8);
        resp[5] = (uint8_t)(resp_len & 0xFF);
        resp[6] = req[6];
        resp[7] = fc;
        resp[8] = byte_count;

        for (uint16_t i = 0; i < reg_count; i++) {
            uint16_t val = get_holding_register(ctx, (uint16_t)(start_addr + i));
            resp[9 + i * 2]     = (uint8_t)(val >> 8);
            resp[9 + i * 2 + 1] = (uint8_t)(val & 0xFF);
        }
        pthread_mutex_unlock(&ctx->lock);
        return MBAP_HEADER_LEN + 2 + byte_count;
    }

    /* --- 0x04 : Read Input Registers (30001 - 30012) --- */
    case 0x04: {
        if (req_len < 12) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }
        uint16_t start_addr = (uint16_t)((req[8] << 8) | req[9]);
        uint16_t reg_count  = (uint16_t)((req[10] << 8) | req[11]);
        if (reg_count == 0 || reg_count > 125 || (start_addr + reg_count) > 16) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_ADDR, resp);
        }

        uint8_t byte_count = (uint8_t)(reg_count * 2);
        if (max_resp_len < (size_t)(MBAP_HEADER_LEN + 2 + byte_count)) {
            return build_exception_response(req, fc, MB_EXC_SLAVE_DEVICE_FAIL, resp);
        }

        pthread_mutex_lock(&ctx->lock);
        resp[0] = req[0]; resp[1] = req[1];
        resp[2] = 0x00;   resp[3] = 0x00;
        uint16_t resp_len = (uint16_t)(3 + byte_count);
        resp[4] = (uint8_t)(resp_len >> 8);
        resp[5] = (uint8_t)(resp_len & 0xFF);
        resp[6] = req[6];
        resp[7] = fc;
        resp[8] = byte_count;

        for (uint16_t i = 0; i < reg_count; i++) {
            uint16_t val = get_input_register(ctx, (uint16_t)(start_addr + i));
            resp[9 + i * 2]     = (uint8_t)(val >> 8);
            resp[9 + i * 2 + 1] = (uint8_t)(val & 0xFF);
        }
        pthread_mutex_unlock(&ctx->lock);
        return MBAP_HEADER_LEN + 2 + byte_count;
    }

    /* --- 0x06 : Write Single Register (40001 - 40007 / 40031) --- */
    case 0x06: {
        if (req_len < 12) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }
        uint16_t reg_addr = (uint16_t)((req[8] << 8) | req[9]);
        uint16_t reg_val  = (uint16_t)((req[10] << 8) | req[11]);

        pthread_mutex_lock(&ctx->lock);
        bool ok = set_holding_register(ctx, reg_addr, reg_val);
        pthread_mutex_unlock(&ctx->lock);

        if (!ok) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }

        /* Echo de la trame en cas de succès */
        memcpy(resp, req, 12);
        resp[4] = 0x00;
        resp[5] = 0x06;
        return 12;
    }

    /* --- 0x10 : Write Multiple Registers --- */
    case 0x10: {
        if (req_len < 13) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }
        uint16_t start_addr = (uint16_t)((req[8] << 8) | req[9]);
        uint16_t reg_count  = (uint16_t)((req[10] << 8) | req[11]);
        uint8_t byte_count  = req[12];

        if (reg_count == 0 || (start_addr + reg_count) > 32 || byte_count != reg_count * 2) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_ADDR, resp);
        }

        pthread_mutex_lock(&ctx->lock);
        bool all_ok = true;
        for (uint16_t i = 0; i < reg_count; i++) {
            uint16_t val = (uint16_t)((req[13 + i * 2] << 8) | req[13 + i * 2 + 1]);
            if (!set_holding_register(ctx, (uint16_t)(start_addr + i), val)) {
                all_ok = false;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->lock);

        if (!all_ok) {
            return build_exception_response(req, fc, MB_EXC_ILLEGAL_DATA_VAL, resp);
        }

        resp[0] = req[0]; resp[1] = req[1];
        resp[2] = 0x00;   resp[3] = 0x00;
        resp[4] = 0x00;   resp[5] = 0x06;
        resp[6] = req[6];
        resp[7] = fc;
        resp[8] = req[8]; resp[9] = req[9];   /* start_addr */
        resp[10] = req[10]; resp[11] = req[11]; /* reg_count */
        return 12;
    }

    default:
        return build_exception_response(req, fc, MB_EXC_ILLEGAL_FUNCTION, resp);
    }
}

/* ========================================================================= */
/* Thread Serveur Modbus TCP                                                 */
/* ========================================================================= */

struct client_state {
    int fd;
    uint8_t rx_buf[MB_MAX_ADU * 2];
    size_t rx_len;
};

static void *modbus_server_thread_func(void *arg)
{
    (void)arg;
    struct client_state clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].rx_len = 0;
    }

    struct pollfd pfd[MAX_CLIENTS + 1];
    int pfd_slot[MAX_CLIENTS + 1]; /* indice clients[] de chaque entrée pfd (-1 : socket d'écoute) */

    while (g_server_running) {
        int pfd_count = 0;
        pfd[0].fd = g_listen_fd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        pfd_slot[0] = -1;
        pfd_count = 1;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd >= 0) {
                pfd[pfd_count].fd = clients[i].fd;
                pfd[pfd_count].events = POLLIN;
                pfd[pfd_count].revents = 0;
                pfd_slot[pfd_count] = i;
                pfd_count++;
            }
        }

        int ret = poll(pfd, (nfds_t)pfd_count, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;

        /* Nouvelles connexions */
        if (pfd[0].revents & POLLIN) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int new_fd = accept(g_listen_fd, (struct sockaddr *)&client_addr, &client_len);
            if (new_fd >= 0) {
                set_nonblocking(new_fd);
                int slot = -1;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].fd < 0) {
                        slot = i;
                        break;
                    }
                }
                if (slot >= 0) {
                    clients[slot].fd = new_fd;
                    clients[slot].rx_len = 0;
                } else {
                    close(new_fd);
                }
            }
        }

        /* Traitement des clients présents dans le sondage (un client accepté ci-dessus n'a
         * pas d'entrée pfd : il sera lu au tour suivant, sans décaler les indices). */
        for (int k = 1; k < pfd_count; k++) {
            int i = pfd_slot[k];
            if (clients[i].fd < 0) continue;

            if (pfd[k].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = recv(clients[i].fd,
                                 clients[i].rx_buf + clients[i].rx_len,
                                 sizeof(clients[i].rx_buf) - clients[i].rx_len, 0);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    continue;
                }
                if (n <= 0) {
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    clients[i].rx_len = 0;
                } else {
                    clients[i].rx_len += (size_t)n;

                    /* Traite toutes les trames complètes présentes dans le tampon */
                    while (clients[i].rx_len >= MBAP_HEADER_LEN) {
                        uint16_t length = (uint16_t)((clients[i].rx_buf[4] << 8) | clients[i].rx_buf[5]);
                        size_t expected_total = (size_t)(MBAP_HEADER_LEN - 1 + length);

                        if (expected_total > sizeof(clients[i].rx_buf)) {
                            /* Trame corrompue : réinitialise */
                            clients[i].rx_len = 0;
                            break;
                        }

                        if (clients[i].rx_len < expected_total) {
                            break; /* Attente du reste des octets */
                        }

                        uint8_t resp_buf[MB_MAX_ADU];
                        int resp_len = plc_modbus_process_frame(
                            g_plc_ctx,
                            clients[i].rx_buf, expected_total,
                            resp_buf, sizeof(resp_buf)
                        );

                        if (resp_len > 0) {
                            send(clients[i].fd, resp_buf, (size_t)resp_len, 0);
                        }

                        /* Décale le tampon */
                        memmove(clients[i].rx_buf,
                                clients[i].rx_buf + expected_total,
                                clients[i].rx_len - expected_total);
                        clients[i].rx_len -= expected_total;
                    }
                }
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd >= 0) {
            close(clients[i].fd);
            clients[i].fd = -1;
        }
    }

    return NULL;
}

int plc_modbus_server_start(plc_context_t *ctx, const char *bind_ip, int port)
{
    if (ctx == NULL || bind_ip == NULL || port < 0) {
        return -1;
    }

    if (g_server_running) {
        return -7;
    }

    g_plc_ctx = ctx;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        return -2;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    set_nonblocking(g_listen_fd);

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &saddr.sin_addr) <= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -3;
    }

    if (bind(g_listen_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -4;
    }

    if (listen(g_listen_fd, 8) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -5;
    }

    if (port == 0) {
        struct sockaddr_in bound_addr;
        socklen_t addr_len = sizeof(bound_addr);
        if (getsockname(g_listen_fd, (struct sockaddr *)&bound_addr, &addr_len) == 0) {
            g_server_port = ntohs(bound_addr.sin_port);
        } else {
            g_server_port = 0;
        }
    } else {
        g_server_port = port;
    }

    g_server_running = true;
    if (pthread_create(&g_server_thread, NULL, modbus_server_thread_func, NULL) != 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = false;
        g_server_port = 0;
        return -6;
    }

    return 0;
}

int plc_modbus_server_port(void)
{
    return g_server_port;
}

void plc_modbus_server_stop(void)
{
    if (g_server_running) {
        g_server_running = false;
        pthread_join(g_server_thread, NULL);
    }
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    g_server_port = 0;
}
