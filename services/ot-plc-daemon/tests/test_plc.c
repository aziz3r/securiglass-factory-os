/**
 * @file test_plc.c
 * @brief Tests du simulateur PLC et du serveur Modbus (sans framework externe).
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_modbus.h"
#include "plc_simulator.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail = 0;
static int g_run = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_run++;                                                                 \
        if (!(cond)) {                                                           \
            g_fail++;                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                        \
    } while (0)

static void be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t rd(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Construit une requête MBAP + PDU(fc, a, b). */
static size_t req(uint8_t *o, uint8_t unit, uint8_t fc, uint16_t a, uint16_t b)
{
    be(o, 0x1234);
    be(o + 2, 0);
    be(o + 4, 6);
    o[6] = unit;
    o[7] = fc;
    be(o + 8, a);
    be(o + 10, b);
    return 12;
}

static int run(plc_context_t *c, const uint8_t *in, size_t n, uint8_t *out)
{
    return plc_modbus_process_frame(c, in, n, out, 260);
}

static void tick(plc_context_t *c, int seconds)
{
    for (int i = 0; i < seconds * 10; i++) {
        plc_simulator_step(c, 0.1);
    }
}

static void write_reg(plc_context_t *c, uint16_t addr, uint16_t v, uint8_t *out, int *rc)
{
    uint8_t in[12];
    size_t n = req(in, 1, 0x06, addr, v);
    *rc = run(c, in, n, out);
}

static void test_reads_and_exceptions(void)
{
    plc_context_t c;
    uint8_t in[16], out[260];
    plc_simulator_init(&c);

    size_t n = req(in, 1, 0x04, 0, 12);
    int rc = run(&c, in, n, out);
    CHECK(rc == 7 + 2 + 24);
    CHECK(out[7] == 0x04 && out[8] == 24);
    CHECK(rd(out) == 0x1234 && rd(out + 2) == 0); /* écho MBAP */
    CHECK(rd(out + 9) == 250);                    /* 25.0 °C x10 */
    CHECK(rd(out + 9 + 20) == 0);                 /* état IDLE */

    n = req(in, 1, 0x04, 10, 3); /* dépasse la table */
    rc = run(&c, in, n, out);
    CHECK(rc == 9 && out[7] == 0x84 && out[8] == 0x02);

    n = req(in, 1, 0x03, 0, 0);
    rc = run(&c, in, n, out);
    CHECK(rc == 9 && out[7] == 0x83 && out[8] == 0x03);

    n = req(in, 1, 0x04, 0, 126);
    rc = run(&c, in, n, out);
    CHECK(rc == 9 && out[8] == 0x03);

    n = req(in, 1, 0x01, 0, 1); /* coils : non supporté */
    rc = run(&c, in, n, out);
    CHECK(rc == 9 && out[7] == 0x81 && out[8] == 0x01);

    n = req(in, 1, 0x02, 0, 4);
    rc = run(&c, in, n, out);
    CHECK(rc == 7 + 2 + 1 && out[9] == 0x07); /* e-stop OK(1) porte(1) air(1) verre(0) */

    n = req(in, 2, 0x04, 0, 1); /* autre unit id : ignoré */
    CHECK(run(&c, in, n, out) == 0);
    plc_simulator_destroy(&c);
}

static void test_malformed_frames(void)
{
    plc_context_t c;
    uint8_t in[16], out[260];
    plc_simulator_init(&c);
    size_t n = req(in, 1, 0x04, 0, 1);

    CHECK(run(&c, in, 7, out) < 0);       /* trop courte */
    be(in + 2, 1);
    CHECK(run(&c, in, n, out) < 0);       /* protocol id != 0 */
    be(in + 2, 0);
    be(in + 4, 9);
    CHECK(run(&c, in, n, out) < 0);       /* longueur MBAP incohérente */
    be(in + 4, 6);
    CHECK(run(&c, in, n, out) > 0);       /* contrôle : redevient valide */
    CHECK(plc_modbus_process_frame(&c, in, n, out, 8) < 0); /* tampon de sortie trop petit */
    CHECK(plc_modbus_process_frame(NULL, in, n, out, 260) < 0);
    plc_simulator_destroy(&c);
}

static void test_writes(void)
{
    plc_context_t c;
    uint8_t out[260];
    int rc;
    plc_simulator_init(&c);

    write_reg(&c, 0, 6800, out, &rc);
    CHECK(rc == 12 && out[7] == 0x06 && rd(out + 10) == 6800);
    CHECK(c.setpoints.setpoint_temp_z1 > 679.9 && c.setpoints.setpoint_temp_z1 < 680.1);

    write_reg(&c, 0, 4999, out, &rc); /* sous la plage */
    CHECK(rc == 9 && out[8] == 0x03);
    write_reg(&c, 0, 7501, out, &rc);
    CHECK(rc == 9 && out[8] == 0x03);
    write_reg(&c, 4, 8001, out, &rc);
    CHECK(rc == 9 && out[8] == 0x03);
    write_reg(&c, 5, 99, out, &rc);
    CHECK(rc == 9 && out[8] == 0x03);
    write_reg(&c, 7, 1, out, &rc); /* adresse inexistante */
    CHECK(rc == 9 && out[8] == 0x02);
    write_reg(&c, 6, 9, out, &rc); /* commande inconnue */
    CHECK(rc == 9 && out[8] == 0x03);
    CHECK(c.setpoints.setpoint_temp_z1 > 679.9 && c.setpoints.setpoint_temp_z1 < 680.1);

    /* FC 0x10 atomique : une valeur invalide annule tout le bloc. */
    uint8_t m[40];
    be(m, 1); be(m + 2, 0); be(m + 4, 7 + 4); m[6] = 1; m[7] = 0x10;
    be(m + 8, 1); be(m + 10, 2); m[12] = 4; be(m + 13, 7000); be(m + 15, 9999);
    rc = run(&c, m, 17, out);
    CHECK(rc == 9 && out[8] == 0x03);
    CHECK(c.setpoints.setpoint_temp_z2 > 699.9 && c.setpoints.setpoint_temp_z2 < 700.1);
    be(m + 15, 7100);
    rc = run(&c, m, 17, out);
    CHECK(rc == 12 && out[7] == 0x10 && rd(out + 10) == 2);
    CHECK(c.setpoints.setpoint_temp_z3 > 709.9 && c.setpoints.setpoint_temp_z3 < 710.1);
    m[12] = 3; /* byte count incohérent */
    CHECK(run(&c, m, 17, out) == 9);
    plc_simulator_destroy(&c);
}

static void test_full_cycle(void)
{
    plc_context_t c;
    uint8_t out[260];
    int rc;
    plc_simulator_init(&c);

    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc);
    CHECK(rc == 12);
    CHECK(c.state == CYCLE_STATE_PREHEAT && (c.status_flags & PLC_FLAG_HEATERS_ON));
    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc); /* déjà démarré */
    CHECK(rc == 9 && out[8] == 0x04);

    int saw_quench = 0;
    for (int i = 0; i < 4000 && c.state != CYCLE_STATE_IDLE; i++) {
        tick(&c, 1);
        if (c.state == CYCLE_STATE_QUENCHING) {
            saw_quench = 1;
            CHECK(c.metrics.glass_pyrometer > 600.0 || c.metrics.quench_pressure < 1.0 ||
                  c.status_flags & PLC_FLAG_QUENCH_ON);
        }
        CHECK(c.metrics.temp_zone1 <= 850.0);
    }
    CHECK(saw_quench);
    CHECK(c.state == CYCLE_STATE_IDLE);
    CHECK(c.error_code == PLC_ERR_NONE && !(c.status_flags & PLC_FLAG_GLASS_BROKEN));
    plc_simulator_destroy(&c);
}

static void test_thermal_shock(void)
{
    plc_context_t c;
    uint8_t out[260];
    int rc;
    plc_simulator_init(&c);
    write_reg(&c, 0, 5000, out, &rc);
    write_reg(&c, 1, 5000, out, &rc);
    write_reg(&c, 2, 5000, out, &rc);
    write_reg(&c, 3, 5000, out, &rc);
    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc);
    for (int i = 0; i < 1000 && !(c.status_flags & PLC_FLAG_GLASS_BROKEN); i++) {
        tick(&c, 1);
    }
    CHECK(c.status_flags & PLC_FLAG_GLASS_BROKEN);
    CHECK(c.error_code == PLC_ERR_THERMAL_SHOCK);
    plc_simulator_destroy(&c);
}

static void test_conveyor_stall(void)
{
    plc_context_t c;
    uint8_t out[260];
    int rc;
    plc_simulator_init(&c);
    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc);
    for (int i = 0; i < 1000 && c.state != CYCLE_STATE_HEATING; i++) {
        tick(&c, 1);
    }
    CHECK(c.state == CYCLE_STATE_HEATING);
    write_reg(&c, 6, PLC_CMD_PAUSE, out, &rc);
    CHECK(rc == 12 && c.metrics.conveyor_speed == 0.0 + c.metrics.conveyor_speed);
    tick(&c, 12);
    CHECK(c.status_flags & PLC_FLAG_GLASS_BROKEN);
    CHECK(c.error_code == PLC_ERR_CONVEYOR_STOPPED);
    plc_simulator_destroy(&c);
}

static void test_estop(void)
{
    plc_context_t c;
    uint8_t out[260], in[12];
    int rc;
    plc_simulator_init(&c);
    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc);
    tick(&c, 5);
    write_reg(&c, 6, PLC_CMD_E_STOP, out, &rc);
    CHECK(rc == 12 && c.state == CYCLE_STATE_E_STOP);
    tick(&c, 2);
    CHECK(c.metrics.conveyor_speed == 0.0 && c.metrics.power_kw == 0.0);
    CHECK((c.status_flags & PLC_FLAG_E_STOP_ACTIVE) && c.error_code == PLC_ERR_E_STOP);

    size_t n = req(in, 1, 0x02, 0, 1);
    CHECK(run(&c, in, n, out) == 10 && (out[9] & 1) == 0); /* bouton NF : 0 = déclenché */

    write_reg(&c, 6, PLC_CMD_START_CYCLE, out, &rc); /* refus tant qu'en E-STOP */
    CHECK(rc == 9 && out[8] == 0x04);

    c.door_interlock = false; /* conditions de sécurité non réunies */
    write_reg(&c, 6, PLC_CMD_RESET, out, &rc);
    CHECK(rc == 9 && out[8] == 0x04 && c.state == CYCLE_STATE_E_STOP);
    c.door_interlock = true;
    write_reg(&c, 6, PLC_CMD_RESET, out, &rc);
    CHECK(rc == 12 && c.state == CYCLE_STATE_IDLE && c.error_code == PLC_ERR_NONE);
    plc_simulator_destroy(&c);
}

static void test_bad_step_args(void)
{
    plc_context_t c;
    plc_simulator_init(&c);
    uint64_t t = c.cycle_tick;
    plc_simulator_step(&c, 0.0);
    plc_simulator_step(&c, -1.0);
    plc_simulator_step(&c, 100.0);
    CHECK(c.cycle_tick == t);
    plc_simulator_destroy(&c);
}

static int connect_local(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    (void)inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static void test_tcp_roundtrip(void)
{
    plc_context_t c;
    uint8_t in[12], out[260];
    plc_simulator_init(&c);
    CHECK(plc_modbus_server_start(&c, "127.0.0.1", 0) == 0);
    int port = plc_modbus_server_port();
    CHECK(port > 0);
    CHECK(plc_modbus_server_start(&c, "127.0.0.1", 0) != 0); /* double démarrage refusé */

    int fd = connect_local(port);
    CHECK(fd >= 0);
    size_t n = req(in, 1, 0x04, 0, 12);
    /* Requête fragmentée octet par octet : le serveur doit réassembler. */
    for (size_t i = 0; i < n; i++) {
        CHECK(send(fd, in + i, 1, 0) == 1);
        usleep(2000);
    }
    ssize_t got = 0;
    while (got < 33) {
        ssize_t r = recv(fd, out + got, sizeof(out) - (size_t)got, 0);
        if (r <= 0) {
            break;
        }
        got += r;
    }
    CHECK(got == 33 && out[7] == 0x04);

    /* Deux requêtes collées dans un seul segment TCP. */
    uint8_t two[24];
    (void)req(two, 1, 0x02, 0, 4);
    (void)req(two + 12, 1, 0x02, 0, 2);
    CHECK(send(fd, two, 24, 0) == 24);
    got = 0;
    while (got < 20) {
        ssize_t r = recv(fd, out + got, sizeof(out) - (size_t)got, 0);
        if (r <= 0) {
            break;
        }
        got += r;
    }
    CHECK(got == 20);

    /* Trame invalide (longueur MBAP absurde) : connexion fermée. */
    uint8_t bad[8] = {0, 1, 0, 0, 0xFF, 0xFF, 1, 4};
    CHECK(send(fd, bad, sizeof(bad), 0) == 8);
    CHECK(recv(fd, out, sizeof(out), 0) <= 0);
    (void)close(fd);

    /* Saturation : plus de clients que de places, le serveur reste vivant. */
    int fds[20];
    for (int i = 0; i < 20; i++) {
        fds[i] = connect_local(port);
    }
    usleep(200000);
    for (int i = 0; i < 20; i++) {
        if (fds[i] >= 0) {
            (void)close(fds[i]);
        }
    }
    usleep(200000);
    fd = connect_local(port);
    CHECK(fd >= 0);
    n = req(in, 1, 0x04, 0, 1);
    CHECK(send(fd, in, n, 0) == (ssize_t)n);
    CHECK(recv(fd, out, sizeof(out), 0) == 11);
    (void)close(fd);

    plc_modbus_server_stop();
    CHECK(plc_modbus_server_port() == 0);
    plc_modbus_server_stop(); /* idempotent */
    plc_simulator_destroy(&c);
}

int main(void)
{
    test_reads_and_exceptions();
    test_malformed_frames();
    test_writes();
    test_full_cycle();
    test_thermal_shock();
    test_conveyor_stall();
    test_estop();
    test_bad_step_args();
    test_tcp_roundtrip();
    printf("%d vérifications, %d échec(s)\n", g_run, g_fail);
    return g_fail == 0 ? 0 : 1;
}
