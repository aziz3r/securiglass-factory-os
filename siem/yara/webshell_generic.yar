/*
  ==========================================================================
  SecuriGlass Factory OS - YARA : webshell generique
  --------------------------------------------------------------------------
  Cible : depots web, sauvegardes, pieces jointes et volumes partages.
  Objectif : detecter les familles de webshells PHP/JSP/ASP les plus
  courantes utilisees pour maintenir un acces sur un poste d'ingenierie.
  Faux positifs : frameworks de test, scripts de maintenance legacy.
  ==========================================================================
*/
rule SecuriGlass_Webshell_Generic
{
    meta:
        author = "SecuriGlass SOC & Red Team"
        description = "Webshell generique PHP/JSP/ASP (execution de commandes, eval obfusque)"
        date = "2026-10-24"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "high"
        tlp = "AMBER"
        scope = "file"

    strings:
        $php_open = "<?php" ascii wide nocase
        $jsp_open = "<%@ page" ascii wide nocase
        $asp_open = "<%@" ascii wide nocase

        $php_eval_post = "eval($_POST" ascii wide nocase
        $php_eval_request = "eval($_REQUEST" ascii wide nocase
        $php_eval_get = "eval($_GET" ascii wide nocase
        $php_system = "system($_" ascii wide nocase
        $php_shell_exec = "shell_exec($_" ascii wide nocase
        $php_passthru = "passthru($_" ascii wide nocase
        $php_assert = "assert($_" ascii wide nocase
        $php_b64 = "base64_decode($_" ascii wide nocase
        $php_preg_e = "preg_replace(\"/.*/e\"" ascii wide nocase

        $jsp_runtime = "Runtime.getRuntime().exec(request.getParameter(" ascii wide nocase
        $jsp_process = "ProcessBuilder(" ascii wide nocase

        $asp_eval = "eval request(" ascii wide nocase
        $asp_execute = "execute request(" ascii wide nocase

        $kit_c99 = "c99shell" ascii wide nocase
        $kit_r57 = "r57shell" ascii wide nocase
        $kit_phpspy = "PHPSPY" ascii wide nocase
        $kit_wso = "WSO 2." ascii wide nocase

    condition:
        filesize < 2MB and
        (
            ($php_open and 2 of ($php_*)) or
            ($jsp_open and any of ($jsp_*)) or
            ($asp_open and any of ($asp_*)) or
            any of ($kit_*)
        )
}
