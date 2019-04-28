import "lisa"

rule test_http_requests_0_MATCH
{
  condition: 
    lisa.network.http_request("GET", /.*/)
}

rule test_http_requests_1_MATCH
{
  condition:
    lisa.network.http_request("POST", /.*/)
}

rule test_http_requests_2_MATCH
{
  condition:
    lisa.network.http_request("GET", /tmUnblock.cgi/)
}

rule test_http_requests_3_MATCH
{
  condition:
    lisa.network.http_request("POST", /^\/tmUnblock.cgi$/)
}

rule test_http_requests_4_MATCH
{
  condition:
    lisa.network.http_request("POST", /.*\.cgi/)
}

rule test_http_request_5_NOT_MATCH
{
  condition:
    lisa.network.http_request("PUT", /.*/)
}

rule test_http_request_6_NOT_MATCH
{
  condition:
    lisa.network.http_request("OPTIONS", /.*/)
}

rule test_http_request_7_NOT_MATCH
{
  condition:
    lisa.network.http_request("GET", /.*\.php/)
}
