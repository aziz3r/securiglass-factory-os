/**
 * @file plc_types.h
 * @brief Types et structures de données pour le simulateur d'automate PLC SecuriGlass
 */

#ifndef PLC_TYPES_H
#define PLC_TYPES_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief État du cycle de trempe thermique (valeurs identiques au registre 30011)
 */
typedef enum {
    CYCLE_STATE_IDLE       = 0,
    CYCLE_STATE_PREHEAT    = 1,
    CYCLE_STATE_HEATING    = 2,
    CYCLE_STATE_QUENCHING  = 3,
    CYCLE_STATE_COOLING    = 4,
    CYCLE_STATE_E_STOP     = 5
} plc_cycle_state_t;

/**
 * @brief Drapeaux d'état process (bitfield du registre 30010, conforme à la spec Étape 2)
 */
typedef enum {
    PLC_FLAG_HEATERS_ON     = (1 << 0),
    PLC_FLAG_QUENCH_ON      = (1 << 1),
    PLC_FLAG_E_STOP_ACTIVE  = (1 << 2),
    PLC_FLAG_GLASS_BROKEN   = (1 << 3)
} plc_status_flags_t;

/** @brief Codes anomalie (registre 30012, 0 = nominal) */
typedef enum {
    PLC_ERR_NONE                = 0,
    PLC_ERR_THERMAL_SHOCK       = 1, /**< THERMAL_SHOCK_BREAKAGE : soufflage sous 620 °C */
    PLC_ERR_CONVEYOR_STOPPED    = 2, /**< THERMAL_SHOCK_BREAKAGE : convoyeur arrêté en chauffe */
    PLC_ERR_E_STOP              = 3,
    PLC_ERR_PNEUMATIC_LOSS      = 4
} plc_error_code_t;

/** @brief Ordres procédé (registre 40007) */
typedef enum {
    PLC_CMD_NONE        = 0,
    PLC_CMD_START_CYCLE = 1,
    PLC_CMD_PAUSE       = 2,
    PLC_CMD_RESUME      = 3,
    PLC_CMD_E_STOP      = 4,
    PLC_CMD_RESET       = 5
} plc_command_t;

/**
 * @brief Modèle thermique des 4 zones du four de trempe
 */
typedef struct {
    double temp_zone1;        /**< Température actuelle Zone 1 (°C) */
    double temp_zone2;        /**< Température actuelle Zone 2 (°C) */
    double temp_zone3;        /**< Température actuelle Zone 3 (°C) */
    double temp_zone4;        /**< Température actuelle Zone 4 (°C) */
    double glass_pyrometer;   /**< Mesure pyromètre optique surface verre (°C) */
    double quench_pressure;   /**< Pression d'air du caisson de soufflage (bar) */
    double conveyor_speed;    /**< Vitesse du convoyeur rouleaux (m/min) */
    double blower_rpm;        /**< Vitesse de rotation des soufflantes (RPM) */
    double power_kw;          /**< Puissance instantanée consommée (kW) */
} plc_process_metrics_t;

/**
 * @brief Consignes opératoires fixées par les Holding Registers
 */
typedef struct {
    double setpoint_temp_z1;  /**< Consigne T° Zone 1 (°C) */
    double setpoint_temp_z2;  /**< Consigne T° Zone 2 (°C) */
    double setpoint_temp_z3;  /**< Consigne T° Zone 3 (°C) */
    double setpoint_temp_z4;  /**< Consigne T° Zone 4 (°C) */
    double setpoint_quench;   /**< Consigne Pression Trempe (bar) */
    double setpoint_speed;    /**< Consigne Vitesse Convoyeur (m/min) */
} plc_setpoints_t;

/**
 * @brief Contexte global de l'automate PLC
 */
typedef struct {
    plc_cycle_state_t state;
    uint16_t status_flags;
    uint16_t error_code;
    plc_process_metrics_t metrics;
    plc_setpoints_t setpoints;
    bool emergency_stop;
    bool door_interlock;
    bool air_pressure_switch;
    bool glass_sensor;
    bool paused;
    uint16_t last_command;
    double state_time;        /**< Temps passé dans l'état courant (s simulées) */
    double stall_time;        /**< Temps d'arrêt convoyeur en zone de chauffe (s) */
    uint64_t cycle_tick;
    time_t last_update;
    pthread_mutex_t lock;     /**< Protège tout le contexte (simulateur + serveur Modbus) */
} plc_context_t;

#endif /* PLC_TYPES_H */
