import "lisa"

rule test_irc_0_MATCH
{
  condition: 
    lisa.network.irc(/^JOIN/)
}

rule test_irc_1_MATCH
{
  condition:
    lisa.network.irc(/^JOIN #randomserver$/)
}

rule test_irc_2_MATCH
{
  condition:
    lisa.network.irc(/PRIVMSG/)
}

rule test_irc_3_MATCH
{
  condition:
    lisa.network.irc(/NOTICE/)
}

rule test_irc_4_MATCH
{
  condition:
    lisa.network.irc(/:Test message./)
}

rule test_irc_5_MATCH
{
  condition:
    lisa.network.irc(/^PRIVMSG test/)
}

rule test_irc_6_NOT_MATCH
{
  condition:
    lisa.network.irc(/^R.*/)
}

rule test_irc_7_NOT_MATCH
{
  condition:
    lisa.network.irc(/PING/)
}

rule test_irc_8_NOT_MATCH
{
  condition:
    lisa.network.irc(/.*a$/)
}
