"""Outils Red Team Modbus/TCP du PoC SecuriGlass Factory OS.

Ce paquet est reserve aux tests d'intrusion autorises sur le perimetre du
laboratoire (127.0.0.1 ou 10.10.30.0/24, port 5020). Toute utilisation hors
de ce perimetre est interdite. Voir `README.md` et `guardrails.py`.
"""

__all__ = ["guardrails", "modbus_proto", "cli_common"]
