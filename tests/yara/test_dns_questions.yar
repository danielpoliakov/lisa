import "lisa"

rule test_dns_question_0_MATCH
{
  condition: 
    lisa.network.dns_question(/test2.cz/, "ANY")
}

rule test_dns_question_1_MATCH
{
  condition:
    lisa.network.dns_question(/^l.ocalhost.host$/, "A")
}

rule test_dns_question_2_MATCH
{
  condition:
    lisa.network.dns_question(/.*\.com/, "AAAA")
}

rule test_dns_question_3_MATCH
{
  condition:
    lisa.network.dns_question(/^test2\.test2\.cz$/, "CNAME")
}

rule test_dns_question_4_MATCH
{
  condition:
    lisa.network.dns_question(/.*\.cz/, "ANY")
}

rule test_dns_question_5_NOT_MATCH
{
  condition:
    lisa.network.dns_question(/^test2\.cz$/, "ANY")
}

rule test_dns_question_6_NOT_MATCH
{
  condition:
    lisa.network.dns_question(/.*/, "MX")
}

rule test_dns_question_7_NOT_MATCH
{
  condition:
    lisa.network.dns_question(/localhost\.host/, "A")
}
