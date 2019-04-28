import "lisa"

rule test_syn_scan_0_MATCH
{
  condition: 
    lisa.network.syn_scan()
}

rule test_blacklisted_ip_access_0_MATCH
{
  condition:
    lisa.network.blacklisted_ip_access()
}
