rule Arbitraitor_Suspicious_CurlPipeShell : suspicious_shell downloader
{
  meta:
    description = "Downloads content and pipes it directly into a shell"
    source = "arbitraitor-builtin"
  strings:
    $curl = "curl" ascii nocase
    $wget = "wget" ascii nocase
    $pipe_sh = /\|\s*(sudo\s+)?(ba)?sh\b/ ascii
  condition:
    any of ($curl, $wget) and $pipe_sh
}

rule Arbitraitor_Suspicious_Powershell_DownloadCradle : suspicious_powershell downloader
{
  meta:
    description = "PowerShell download cradle pattern"
    source = "arbitraitor-builtin"
  strings:
    $webclient = "System.Net.WebClient" ascii nocase
    $download = "DownloadString" ascii nocase
    $iex = "IEX" ascii nocase
  condition:
    $webclient and $download and $iex
}
