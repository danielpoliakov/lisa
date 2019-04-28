import "lisa"

rule test_file_open_0_MATCH
{
  condition: 
    lisa.behaviour.file_open(/^\/dev\/watchdog$/)
}

rule test_file_open_1_MATCH
{
  condition:
    lisa.behaviour.file_open(/\/proc/)
}

rule test_file_open_2_MATCH
{
  condition:
    lisa.behaviour.file_open(/.*/)
}

rule test_file_open_3_NOT_MATCH
{
  condition:
    lisa.behaviour.file_open(/shouldnotmatch/)
}

rule test_file_open_4_NOT_MATCH
{
  condition:
    lisa.behaviour.file_open(/^s.*/)
}
