/**
 * @file plc_simulator.h
 * @brief Moteur de simulation physique du four de trempe SecuriGlass
 */

#ifndef PLC_SIMULATOR_H
#define PLC_SIMULATOR_H

#include "plc_types.h"

/**
 * @brief Initialise le contexte de simulation du four
 * @param ctx Pointeur vers le contexte automate
 */
void plc_simulator_init(plc_context_t *ctx);

/**
 * @brief Met à jour les variables thermiques et la cinématique pour un pas de temps dt
 * @param ctx Pointeur vers le contexte automate
 * @param dt_seconds Intervalle de temps écoulé en secondes
 */
void plc_simulator_step(plc_context_t *ctx, double dt_seconds);

/**
 * @brief Déclenche un arrêt d'urgence matériel (le verrou doit être détenu)
 * @param ctx Pointeur vers le contexte automate
 */
void plc_trigger_estop(plc_context_t *ctx);

/**
 * @brief Réarme l'automate après un arrêt d'urgence
 * @param ctx Pointeur vers le contexte automate
 * @return true si réarmement réussi, false si conditions de sécurité non réunies
 */
bool plc_reset_estop(plc_context_t *ctx);

/**
 * @brief Détruit les ressources du contexte (mutex)
 * @param ctx Pointeur vers le contexte automate
 */
void plc_simulator_destroy(plc_context_t *ctx);

/**
 * @brief Applique un ordre procédé (registre 40007). Le verrou doit être détenu.
 * @param ctx Contexte automate
 * @param command Code ordre (voir plc_command_t)
 * @return true si l'ordre est accepté dans l'état courant, false sinon
 */
bool plc_apply_command(plc_context_t *ctx, uint16_t command);

#endif /* PLC_SIMULATOR_H */
