import "lisa"

rule test_endpoint_ip_0_MATCH
{
  condition: 
    lisa.network.endpoint_ip("8.8.8.8")
}

rule test_endpoint_ip_1_MATCH
{
  condition: 
    lisa.network.endpoint_ip("167.160.186.125")
}

rule test_endpoint_ip_2_MATCH
{
  condition:
    lisa.network.endpoint_ip("36.74.130.194")
}

rule test_endpoint_ip_3_MATCH
{
  condition:
    lisa.network.endpoint_ip("196.16.183.230")
}

rule test_endpoint_ip_4_MATCH
{
  condition:
    lisa.network.endpoint_ip("170.158.158.149")
}

rule test_endpoint_ip_5_MATCH
{
  condition:
    lisa.network.endpoint_ip("37.59.72.2")
}

rule test_endpoint_ip_6_NOT_MATCH
{
  condition:
    lisa.network.endpoint_ip("10.0.0.1")
}

rule test_endpoint_ip_7_NOT_MATCH
{
  condition:
    lisa.network.endpoint_ip("192.168.0.1")
}

rule test_endpoint_ip_8_NOT_MATCH
{
  condition:
    lisa.network.endpoint_ip("158.140.58.20")
}

rule test_endpoint_ip_9_NOT_MATCH
{
  condition:
    lisa.network.endpoint_ip("173.21.34.5")
}
