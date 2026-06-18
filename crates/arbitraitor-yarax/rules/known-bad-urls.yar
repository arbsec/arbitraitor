rule Arbitraitor_Known_Eicar_Test_String : malware test_signature
{
  meta:
    description = "EICAR anti-malware test string"
    source = "arbitraitor-builtin"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
  condition:
    $eicar
}

rule Arbitraitor_Known_Bad_Url_Example : known_bad_url network_indicator
{
  meta:
    description = "Known malicious URL pattern used by tests and examples"
    source = "arbitraitor-builtin"
  strings:
    $url = "http://malware.example.test/payload" ascii nocase
  condition:
    $url
}
