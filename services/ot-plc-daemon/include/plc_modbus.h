/**
 * @file plc_modbus.h
 * @brief Serveur Modbus TCP durci pour automate PLC SecuriGlass
 */

#ifndef PLC_MODBUS_H
#define PLC_MODBUS_H

#include "plc_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Démarre le serveur Modbus TCP
 * @param ctx Contexte automate partagé
 * @param bind_ip Adresse IP d'écoute (ex: "127.0.0.1" ou "0.0.0.0")
 * @param port Port TCP d'écoute (standard: 5020)
 * @return 0 en cas de succès, code d'erreur négatif sinon
 */
int plc_modbus_server_start(plc_context_t *ctx, const char *bind_ip, int port);

/**
 * @brief Port TCP effectivement lié (utile avec port = 0 en test)
 * @return Port d'écoute, ou 0 si le serveur n'est pas démarré
 */
int plc_modbus_server_port(void);

/**
 * @brief Arrête proprement le serveur Modbus TCP et libère les sockets
 */
void plc_modbus_server_stop(void);

/**
 * @brief Traite une trame de requête Modbus TCP (MBAP + PDU)
 * @param ctx Contexte automate
 * @param req_buf Tampon de requête
 * @param req_len Longueur de la requête
 * @param resp_buf Tampon de réponse (alloué par l'appelant)
 * @param max_resp_len Taille maximale disponible
 * @return > 0 : octets de réponse à émettre ; 0 : requête ignorée sans réponse (autre Unit ID) ;
 *         < 0 : violation de protocole (le serveur ferme la connexion)
 */
int plc_modbus_process_frame(plc_context_t *ctx,
                             const uint8_t *req_buf, size_t req_len,
                             uint8_t *resp_buf, size_t max_resp_len);

#endif /* PLC_MODBUS_H */
