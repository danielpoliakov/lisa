import "lisa"

rule test_syscall_0_MATCH
{
  condition: 
    lisa.behavior.syscall("connect", /.*/)
}

rule test_syscall_1_MATCH
{
  condition:
    lisa.behavior.syscall("connect", /{AF_INET, 8.8.8.8, 53}/)
}

rule test_syscall_2_MATCH
{
  condition:
    lisa.behavior.syscall("write", /Sister finger, Sister finger, were are you./)
}

rule test_syscall_3_MATCH
{
  condition:
    lisa.behavior.syscall("sendto", /.*/)
}

rule test_syscall_4_MATCH
{
  condition:
    lisa.behavior.syscall("socket", /PF_INET, SOCK_STREAM, IPPROTO_IP/)
}

rule test_syscall_5_MATCH
{
  condition:
    lisa.behavior.syscall("send", /POST \/tmBlock.cgi/)
}

rule test_syscall_6_NOT_MATCH
{
  condition:
    lisa.behavior.syscall("notsyscallname", /.*/)
}

rule test_syscall_7_NOT_MATCH
{
  condition:
    lisa.behavior.syscall("socket", /PF_NOTEXIST/)
}

rule test_syscall_8_NOT_MATCH
{
  condition:
    lisa.behavior.syscall("connect", /{AF_INET, 177.234.228.2, 42}/)
}
