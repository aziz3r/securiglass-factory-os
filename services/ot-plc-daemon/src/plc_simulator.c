/**
 * @file plc_simulator.c
 * @brief Simulation physique du four de trempe (EN 12150) : chauffe 4 zones, trempe, casse thermique.
 *
 * Aucune allocation dynamique. plc_simulator_step() prend le verrou du contexte ;
 * plc_apply_command(), plc_trigger_estop() et plc_reset_estop() exigent qu'il soit détenu.
 */

#define _POSIX_C_SOURCE 200809L

#include "plc_simulator.h"

#include <math.h>
#include <string.h>

#define T_AMBIENT_C 25.0
#define ALPHA_HEAT 0.030           /* gain de chauffe (1/s) */
#define BETA_LOSS 0.0005           /* pertes thermiques (1/s) */
#define GLASS_COUPLING 0.040       /* couplage verre <-> moyenne des zones (1/s) */
#define GLASS_QUENCH_RATE 0.150    /* refroidissement verre sous soufflage (1/s) */
#define COOL_NATURAL_RATE 0.010    /* refroidissement zones four éteint (1/s) */
#define MIN_QUENCH_GLASS_C 620.0   /* sous ce seuil, le soufflage casse le verre */
#define PREHEAT_MARGIN_C 20.0
#define SOAK_MARGIN_C 10.0
#define MAX_SOAK_S 120.0
#define QUENCH_DURATION_S 12.0
#define COOLED_GLASS_C 80.0
#define STALL_BREAK_S 10.0
#define PRESSURE_RAMP_BAR_S 1.5
#define ZONE_FULL_POWER_KW 60.0
#define BLOWER_MAX_KW 45.0
#define BLOWER_MAX_RPM 3000.0
#define BLOWER_RATED_BAR 6.5

#define TEMP_SP_MIN 500.0
#define TEMP_SP_MAX 750.0

static double *zone_temp(plc_process_metrics_t *m, int zone)
{
    switch (zone) {
    case 0: return &m->temp_zone1;
    case 1: return &m->temp_zone2;
    case 2: return &m->temp_zone3;
    default: return &m->temp_zone4;
    }
}

static double zone_setpoint(const plc_setpoints_t *sp, int zone)
{
    switch (zone) {
    case 0: return sp->setpoint_temp_z1;
    case 1: return sp->setpoint_temp_z2;
    case 2: return sp->setpoint_temp_z3;
    default: return sp->setpoint_temp_z4;
    }
}

static double clampd(double v, double lo, double hi)
{
    if (v < lo) {
        return lo;
    }
    return v > hi ? hi : v;
}

static void set_state(plc_context_t *ctx, plc_cycle_state_t state)
{
    ctx->state = state;
    ctx->state_time = 0.0;
}

static void update_flags(plc_context_t *ctx)
{
    uint16_t keep = (uint16_t)(ctx->status_flags & PLC_FLAG_GLASS_BROKEN);
    if (ctx->state == CYCLE_STATE_PREHEAT || ctx->state == CYCLE_STATE_HEATING) {
        keep |= PLC_FLAG_HEATERS_ON;
    }
    if (ctx->state == CYCLE_STATE_QUENCHING) {
        keep |= PLC_FLAG_QUENCH_ON;
    }
    if (ctx->state == CYCLE_STATE_E_STOP || ctx->emergency_stop) {
        keep |= PLC_FLAG_E_STOP_ACTIVE;
    }
    ctx->status_flags = keep;
}

void plc_simulator_init(plc_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = CYCLE_STATE_IDLE;
    ctx->metrics.temp_zone1 = T_AMBIENT_C;
    ctx->metrics.temp_zone2 = T_AMBIENT_C;
    ctx->metrics.temp_zone3 = T_AMBIENT_C;
    ctx->metrics.temp_zone4 = T_AMBIENT_C;
    ctx->metrics.glass_pyrometer = T_AMBIENT_C;
    ctx->setpoints.setpoint_temp_z1 = 700.0;
    ctx->setpoints.setpoint_temp_z2 = 700.0;
    ctx->setpoints.setpoint_temp_z3 = 700.0;
    ctx->setpoints.setpoint_temp_z4 = 700.0;
    ctx->setpoints.setpoint_quench = 4.0;
    ctx->setpoints.setpoint_speed = 4.5;
    ctx->door_interlock = true;
    ctx->air_pressure_switch = true;
    ctx->glass_sensor = false;
    (void)pthread_mutex_init(&ctx->lock, NULL);
}

void plc_simulator_destroy(plc_context_t *ctx)
{
    (void)pthread_mutex_destroy(&ctx->lock);
}

void plc_trigger_estop(plc_context_t *ctx)
{
    ctx->emergency_stop = true;
    ctx->paused = false;
    ctx->error_code = PLC_ERR_E_STOP;
    ctx->metrics.conveyor_speed = 0.0;
    set_state(ctx, CYCLE_STATE_E_STOP);
    update_flags(ctx);
}

bool plc_reset_estop(plc_context_t *ctx)
{
    if (ctx->state != CYCLE_STATE_E_STOP) {
        return false;
    }
    if (ctx->emergency_stop || !ctx->door_interlock || !ctx->air_pressure_switch) {
        return false;
    }
    ctx->error_code = PLC_ERR_NONE;
    ctx->status_flags = 0;
    ctx->glass_sensor = false;
    set_state(ctx, CYCLE_STATE_IDLE);
    update_flags(ctx);
    return true;
}

bool plc_apply_command(plc_context_t *ctx, uint16_t command)
{
    ctx->last_command = command;
    switch (command) {
    case PLC_CMD_NONE:
        return true;
    case PLC_CMD_START_CYCLE:
        if (ctx->state != CYCLE_STATE_IDLE || ctx->emergency_stop || !ctx->door_interlock ||
            !ctx->air_pressure_switch) {
            return false;
        }
        ctx->glass_sensor = true;
        ctx->paused = false;
        ctx->stall_time = 0.0;
        ctx->error_code = PLC_ERR_NONE;
        ctx->status_flags = 0;
        set_state(ctx, CYCLE_STATE_PREHEAT);
        update_flags(ctx);
        return true;
    case PLC_CMD_PAUSE:
        if (ctx->state == CYCLE_STATE_IDLE || ctx->state == CYCLE_STATE_E_STOP) {
            return false;
        }
        ctx->paused = true;
        return true;
    case PLC_CMD_RESUME:
        if (!ctx->paused) {
            return false;
        }
        ctx->paused = false;
        ctx->stall_time = 0.0;
        return true;
    case PLC_CMD_E_STOP:
        plc_trigger_estop(ctx);
        return true;
    case PLC_CMD_RESET:
        return plc_reset_estop(ctx);
    default:
        return false;
    }
}

static void break_glass(plc_context_t *ctx, plc_error_code_t code)
{
    ctx->status_flags |= PLC_FLAG_GLASS_BROKEN;
    ctx->error_code = (uint16_t)code;
    /* Casse : arrêt de la trempe, retour en refroidissement contrôlé. */
    set_state(ctx, CYCLE_STATE_COOLING);
}

static void step_thermal(plc_context_t *ctx, double dt)
{
    plc_process_metrics_t *m = &ctx->metrics;
    bool heaters = (ctx->state == CYCLE_STATE_PREHEAT || ctx->state == CYCLE_STATE_HEATING);
    double duty_sum = 0.0;

    for (int z = 0; z < 4; z++) {
        double *t = zone_temp(m, z);
        double sp = clampd(zone_setpoint(&ctx->setpoints, z), TEMP_SP_MIN, TEMP_SP_MAX);
        if (heaters) {
            double gain = ALPHA_HEAT * (sp - *t);
            duty_sum += clampd(gain / (ALPHA_HEAT * 100.0), 0.0, 1.0);
            *t += (gain - BETA_LOSS * (*t - T_AMBIENT_C)) * dt;
        } else {
            *t -= COOL_NATURAL_RATE * (*t - T_AMBIENT_C) * dt;
        }
        *t = clampd(*t, T_AMBIENT_C - 5.0, 850.0);
    }

    double avg = (m->temp_zone1 + m->temp_zone2 + m->temp_zone3 + m->temp_zone4) / 4.0;
    if (ctx->glass_sensor) {
        if (ctx->state == CYCLE_STATE_QUENCHING) {
            m->glass_pyrometer -= GLASS_QUENCH_RATE * (m->glass_pyrometer - T_AMBIENT_C) * dt;
        } else if (heaters) {
            m->glass_pyrometer += GLASS_COUPLING * (avg - m->glass_pyrometer) * dt;
        } else {
            m->glass_pyrometer -= COOL_NATURAL_RATE * 2.0 * (m->glass_pyrometer - T_AMBIENT_C) * dt;
        }
    } else {
        m->glass_pyrometer = avg > T_AMBIENT_C + 5.0 ? avg : T_AMBIENT_C;
    }
    m->glass_pyrometer = clampd(m->glass_pyrometer, T_AMBIENT_C - 5.0, 850.0);

    /* Soufflante : rampe de pression pendant la trempe, retour à 0 sinon. */
    double target_bar = (ctx->state == CYCLE_STATE_QUENCHING) ? ctx->setpoints.setpoint_quench : 0.0;
    double dp = PRESSURE_RAMP_BAR_S * dt;
    if (m->quench_pressure < target_bar) {
        m->quench_pressure = fmin(target_bar, m->quench_pressure + dp);
    } else {
        m->quench_pressure = fmax(target_bar, m->quench_pressure - dp);
    }
    m->blower_rpm = BLOWER_MAX_RPM * clampd(m->quench_pressure / BLOWER_RATED_BAR, 0.0, 1.0);
    m->power_kw = ZONE_FULL_POWER_KW * duty_sum +
                  BLOWER_MAX_KW * clampd(m->quench_pressure / BLOWER_RATED_BAR, 0.0, 1.0);

    /* Convoyeur : tourne en chauffe/trempe, sauf pause ou arrêt d'urgence. */
    bool conveyor_on = ctx->glass_sensor && !ctx->paused && ctx->state != CYCLE_STATE_E_STOP &&
                       ctx->state != CYCLE_STATE_IDLE;
    m->conveyor_speed = conveyor_on ? clampd(ctx->setpoints.setpoint_speed, 1.0, 25.0) : 0.0;
}

static void step_cycle(plc_context_t *ctx, double dt)
{
    plc_process_metrics_t *m = &ctx->metrics;
    ctx->state_time += dt;

    if (!ctx->air_pressure_switch && ctx->state == CYCLE_STATE_QUENCHING) {
        break_glass(ctx, PLC_ERR_PNEUMATIC_LOSS);
        return;
    }

    switch (ctx->state) {
    case CYCLE_STATE_PREHEAT: {
        bool ready = true;
        for (int z = 0; z < 4; z++) {
            if (*zone_temp(m, z) < zone_setpoint(&ctx->setpoints, z) - PREHEAT_MARGIN_C) {
                ready = false;
            }
        }
        if (ready) {
            set_state(ctx, CYCLE_STATE_HEATING);
        }
        break;
    }
    case CYCLE_STATE_HEATING: {
        if (ctx->paused && ctx->glass_sensor) {
            ctx->stall_time += dt;
            if (ctx->stall_time >= STALL_BREAK_S) {
                break_glass(ctx, PLC_ERR_CONVEYOR_STOPPED);
                return;
            }
            break;
        }
        double avg_sp = (ctx->setpoints.setpoint_temp_z1 + ctx->setpoints.setpoint_temp_z2 +
                         ctx->setpoints.setpoint_temp_z3 + ctx->setpoints.setpoint_temp_z4) / 4.0;
        if (m->glass_pyrometer >= avg_sp - SOAK_MARGIN_C || ctx->state_time >= MAX_SOAK_S) {
            if (m->glass_pyrometer < MIN_QUENCH_GLASS_C) {
                break_glass(ctx, PLC_ERR_THERMAL_SHOCK);
                return;
            }
            set_state(ctx, CYCLE_STATE_QUENCHING);
        }
        break;
    }
    case CYCLE_STATE_QUENCHING:
        if (ctx->state_time >= QUENCH_DURATION_S) {
            set_state(ctx, CYCLE_STATE_COOLING);
        }
        break;
    case CYCLE_STATE_COOLING:
        if (m->quench_pressure < 0.05 && m->glass_pyrometer <= COOLED_GLASS_C + 60.0) {
            ctx->glass_sensor = false;
            ctx->paused = false;
            set_state(ctx, CYCLE_STATE_IDLE);
        }
        break;
    case CYCLE_STATE_IDLE:
    case CYCLE_STATE_E_STOP:
    default:
        break;
    }
}

void plc_simulator_step(plc_context_t *ctx, double dt_seconds)
{
    if (!(dt_seconds > 0.0) || dt_seconds > 5.0) {
        return;
    }
    (void)pthread_mutex_lock(&ctx->lock);
    if (ctx->state == CYCLE_STATE_E_STOP) {
        ctx->metrics.conveyor_speed = 0.0;
        ctx->metrics.quench_pressure = 0.0;
        ctx->metrics.blower_rpm = 0.0;
        ctx->metrics.power_kw = 0.0;
        step_thermal(ctx, dt_seconds);
        ctx->metrics.conveyor_speed = 0.0;
        ctx->metrics.power_kw = 0.0;
    } else {
        step_cycle(ctx, dt_seconds);
        step_thermal(ctx, dt_seconds);
    }
    update_flags(ctx);
    ctx->cycle_tick++;
    ctx->last_update = time(NULL);
    (void)pthread_mutex_unlock(&ctx->lock);
}
