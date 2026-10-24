/*
  ==========================================================================
  SecuriGlass Factory OS - YARA : binaire suspect avec chaines de debug OT
  --------------------------------------------------------------------------
  Cible : binaires deposes sur la passerelle edge, la salle de controle ou
  les postes d'ingenierie. Un outil de diagnostic OT legitime ne contient
  pas simultanement des chaines de debug de registres de trempe, des adresses
  du sous-reseau automate et une bibliotheque Modbus generique.
  Faux positifs : SDK constructeur, binaires de maintenance signes.
  ==========================================================================
*/
rule SecuriGlass_OT_Suspicious_Binary
{
    meta:
        author = "SecuriGlass SOC & Red Team"
        description = "Binaire ELF/PE embarquant des chaines de debug OT et une bibliotheque Modbus"
        date = "2026-10-24"
        reference = "https://attack.mitre.org/techniques/T0889/"
        severity = "high"
        tlp = "AMBER"
        scope = "file"

    strings:
        $dbg_tag = "SECURIGLASS_PLC_DEBUG" ascii wide
        $dbg_reg_single = "modbus_write_single_register" ascii
        $dbg_reg_multi = "modbus_write_multiple_registers" ascii
        $dbg_quench = "quench_pressure_bar" ascii
        $dbg_unit = "DEBUG_UNIT_ID" ascii
        $dbg_subnet = "10.10.30." ascii
        $dbg_serial = "/dev/ttyUSB" ascii
        $dbg_autoclave = "autoclave_telemetry" ascii

        $lib_scapy = "scapy" ascii nocase
        $lib_pymodbus = "pymodbus" ascii nocase
        $lib_libmodbus = "libmodbus" ascii nocase

    condition:
        filesize < 50MB and
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        3 of ($dbg_*) and
        any of ($lib_*)
}
