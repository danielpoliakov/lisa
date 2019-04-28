import "lisa"

rule test_telnet_data_0_MATCH
{
  condition: 
    lisa.network.telnet_data(/^Test telnet 1$/)
}

rule test_telnet_data_1_MATCH
{
  condition: 
    lisa.network.telnet_data(/^Test telnet 3$/)
}

rule test_telnet_data_2_MATCH
{
  condition: 
    lisa.network.telnet_data(/.*/)
}

rule test_telnet_data_3_MATCH
{
  condition:
    lisa.network.telnet_data(/T.st/)
}

rule test_telnet_data_4_NOT_MATCH
{
  condition:
    lisa.network.telnet_data(/.*4$/)
}

rule test_telnet_data_5_NOT_MATCH
{
  condition:
    lisa.network.telnet_data(/test/)
}

rule test_telnet_data_6_NOT_MATCH
{
  condition:
    lisa.network.telnet_data(/.*x.*/)
}
