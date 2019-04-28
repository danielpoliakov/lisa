import "lisa"

rule test_processes_0_MATCH
{
  condition: 
    lisa.behavior.number_of_processes() == 5
}

rule test_processes_1_NOT_MATCH
{
  condition:
    lisa.behavior.number_of_processes() < 5
}

rule test_processes_2_NOT_MATCH
{
  condition:
    lisa.behavior.number_of_processes() > 5
}

