import "lisa"

rule test_endpoint_country_0_MATCH
{
  condition: 
    lisa.network.endpoint_country("United States")
}

rule test_endpoint_country_1_MATCH
{
  condition:
    lisa.network.endpoint_country("South Africa")
}

rule test_endpoint_country_2_MATCH
{
  condition:
    lisa.network.endpoint_country("Dominican Republic")
}

rule test_endpoint_country_3_MATCH
{
  condition:
    lisa.network.endpoint_country("Indonesia")
}

rule test_endpoint_country_4_MATCH
{
  condition:
    lisa.network.endpoint_country("Canada")
}


rule test_endpoint_country_5_MATCH
{
  condition:
    lisa.network.endpoint_country("Singapore")
}

rule test_endpoint_country_6_MATCH
{
  condition:
    lisa.network.endpoint_country("Japan")
}

rule test_endpoint_country_7_NOT_MATCH
{
  condition:
    lisa.network.endpoint_country("Czechia")
}

rule test_endpoint_country_8_NOT_MATCH
{
  condition:
    lisa.network.endpoint_country("Slovakia")
}

rule test_endpoint_country_9_NOT_MATCH
{
  condition:
    lisa.network.endpoint_country("Germany")
}

rule test_endpoint_country_10_NOT_MATCH
{
  condition:
    lisa.network.endpoint_country("Russia")
}

rule test_endpoint_country_11_NOT_MATCH
{
  condition:
    lisa.network.endpoint_country("Poland")
}
