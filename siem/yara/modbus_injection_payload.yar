/*
  ==========================================================================
  SecuriGlass Factory OS - YARA : payload d'injection Modbus/TCP
  --------------------------------------------------------------------------
  Cible : captures pcap, journaux binaires de passerelle, files d'attente.
  Objectif : reperer les trames Modbus/TCP d'ECRITURE (FC5, FC6, FC15, FC16)
  et particulierement celles qui ciblent les registres critiques 0-9
  (consignes de trempe, pression, vitesse convoyeur).
  Faux positifs : captures de maintenance volontaires, tests de recette.
  ==========================================================================
*/
rule SecuriGlass_Modbus_Injection_Payload
{
    meta:
        author = "SecuriGlass SOC & Red Team"
        description = "Trame Modbus/TCP d'ecriture (FC5/6/15/16) ou ciblage des registres critiques 0-9"
        date = "2026-10-24"
        reference = "https://attack.mitre.org/techniques/T0836/"
        severity = "high"
        tlp = "AMBER"
        scope = "file"

    strings:
        /* En-tete MBAP : protocol id 00 00 + longueur + unit id + function code.
           La transaction id (2 octets) est variable, on ancre sur 00 00. */
        $mbap_fc05 = { 00 00 00 06 ?? 05 }
        $mbap_fc06 = { 00 00 00 06 ?? 06 }
        $mbap_fc0f_1 = { 00 00 00 08 ?? 0F }
        $mbap_fc10_1 = { 00 00 00 09 ?? 10 }
        $mbap_fc10_2 = { 00 00 00 0B ?? 10 }

        /* Ciblage direct des registres 0x0000 a 0x0009 (consignes procede) */
        $crit_fc06_0 = { 00 00 00 06 ?? 06 00 00 }
        $crit_fc06_1 = { 00 00 00 06 ?? 06 00 01 }
        $crit_fc06_2 = { 00 00 00 06 ?? 06 00 02 }
        $crit_fc10_0 = { 00 00 00 09 ?? 10 00 00 }
        $crit_fc10_1 = { 00 00 00 09 ?? 10 00 01 }

    condition:
        filesize < 10MB and
        (
            2 of ($mbap_fc*) or
            any of ($crit_*)
        )
}
