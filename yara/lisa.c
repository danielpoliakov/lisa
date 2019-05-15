/**
 * Based on cuckoo YARA module:
 * https://github.com/VirusTotal/yara/blob/master/libyara/modules/cuckoo.c
 *
 * Copyright (c) 2014. The YARA Authors. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <jansson.h>
#include <string.h>
#include <yara/modules.h>
#include <yara/re.h>

#define MODULE_NAME lisa

// lisa.behavior.file_open handler
define_function(lisa_behavior_file_open)
{
    YR_SCAN_CONTEXT* context   = scan_context();
    YR_OBJECT* behavior_object = parent();

    json_t* behavior   = (json_t*)behavior_object->data;
    json_t* open_files = json_object_get(behavior, "open_files");
    json_t* value;

    int64_t result = 0;
    size_t index;

    json_array_foreach(open_files, index, value)
    {
        if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0) {
            result = 1;
            break;
        }
    }

    return_integer(result);
}

// lisa.behavour.syscall handler
define_function(lisa_behavior_syscall)
{
    YR_SCAN_CONTEXT* context   = scan_context();
    YR_OBJECT* behavior_object = parent();

    json_t* behavior = (json_t*)behavior_object->data;
    json_t* syscalls = json_object_get(behavior, "syscalls");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* name;
    char* args;

    json_array_foreach(syscalls, index, value)
    {
        if (json_unpack(value, "{s:s, s:s}", "name", &name, "arguments", &args) == 0) {
            if (strcmp(name, string_argument(1)) == 0 && yr_re_match(context, regexp_argument(2), args) > 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// lisa.behavior.number_of_processes handler
define_function(lisa_behavior_number_of_processes)
{
    YR_OBJECT* behavior_object = parent();

    json_t* behavior     = (json_t*)behavior_object->data;
    json_t* processes    = json_object_get(behavior, "processes");
    size_t num_processes = json_array_size(processes);

    return_integer(num_processes);
}

// lisa.network.http_request handler
define_function(lisa_network_http_request)
{
    YR_SCAN_CONTEXT* context  = scan_context();
    YR_OBJECT* network_object = parent();

    json_t* network       = (json_t*)network_object->data;
    json_t* http_requests = json_object_get(network, "http_requests");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* method;
    char* uri;

    json_array_foreach(http_requests, index, value)
    {
        if (json_unpack(value, "{s:s, s:s}", "method", &method, "uri", &uri) == 0) {
            if (strcmp(method, string_argument(1)) == 0 && yr_re_match(context, regexp_argument(2), uri) > 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// lisa.network.dns_question handler
define_function(lisa_network_dns_question)
{
    YR_SCAN_CONTEXT* context  = scan_context();
    YR_OBJECT* network_object = parent();

    json_t* network       = (json_t*)network_object->data;
    json_t* dns_questions = json_object_get(network, "dns_questions");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* name;
    char* type;

    if (strcmp(string_argument(2), "ANY") == 0) {
        json_array_foreach(dns_questions, index, value)
        {
            if (json_unpack(value, "{s:s}", "name", &name) == 0) {
                if (yr_re_match(context, regexp_argument(1), name) > 0) {
                    result = 1;
                    break;
                }
            }
        }
    } else {
        json_array_foreach(dns_questions, index, value)
        {
            if (json_unpack(value, "{s:s, s:s}", "name", &name, "type", &type) == 0) {
                if (yr_re_match(context, regexp_argument(1), name) > 0 && strcmp(type, string_argument(2)) == 0) {
                    result = 1;
                    break;
                }
            }
        }
    }

    return_integer(result);
}

// lisa.network.telnet_data handler
define_function(lisa_network_telnet_data)
{
    YR_SCAN_CONTEXT* context  = scan_context();
    YR_OBJECT* network_object = parent();

    json_t* network     = (json_t*)network_object->data;
    json_t* telnet_data = json_object_get(network, "telnet_data");
    json_t* value;

    int64_t result = 0;
    size_t index;

    json_array_foreach(telnet_data, index, value)
    {
        if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0) {
            result = 1;
            break;
        }
    }

    return_integer(result);
}

// lisa.network.irc handler
define_function(lisa_network_irc)
{
    YR_SCAN_CONTEXT* context  = scan_context();
    YR_OBJECT* network_object = parent();

    json_t* network = (json_t*)network_object->data;
    json_t* irc     = json_object_get(network, "irc_messages");
    json_t* value;

    int64_t result = 0;
    size_t index;

    json_array_foreach(irc, index, value)
    {
        if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0) {
            result = 1;
            break;
        }
    }

    return_integer(result);
}

// lisa.network.endpoint_ip handler
define_function(lisa_network_endpoint_ip)
{
    YR_OBJECT* network_object = parent();

    json_t* network   = (json_t*)network_object->data;
    json_t* endpoints = json_object_get(network, "endpoints");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* ip;

    json_array_foreach(endpoints, index, value)
    {
        if (json_unpack(value, "{s:s}", "ip", &ip) == 0) {
            if (strcmp(ip, string_argument(1)) == 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// lisa.network.endpoint_country handler
define_function(lisa_network_endpoint_country)
{
    YR_OBJECT* network_object = parent();

    json_t* network   = (json_t*)network_object->data;
    json_t* endpoints = json_object_get(network, "endpoints");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* country;

    json_array_foreach(endpoints, index, value)
    {
        if (json_unpack(value, "{s:s}", "country", &country) == 0) {
            if (strcmp(country, string_argument(1)) == 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// lisa.network.syn_scan handler
define_function(lisa_network_syn_scan)
{
    YR_OBJECT* network_object = parent();

    json_t* network   = (json_t*)network_object->data;
    json_t* anomalies = json_object_get(network, "anomalies");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* name;

    json_array_foreach(anomalies, index, value)
    {
        if (json_unpack(value, "{s:s}", "name", &name) == 0) {
            if (strcmp(name, "syn_scan") == 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// lisa.network.blacklisted_ip_access handler
define_function(lisa_network_blacklisted_ip_access)
{
    YR_OBJECT* network_object = parent();

    json_t* network   = (json_t*)network_object->data;
    json_t* anomalies = json_object_get(network, "anomalies");
    json_t* value;

    int64_t result = 0;
    size_t index;

    char* name;

    json_array_foreach(anomalies, index, value)
    {
        if (json_unpack(value, "{s:s}", "name", &name) == 0) {
            if (strcmp(name, "blacklisted_ip_access") == 0) {
                result = 1;
                break;
            }
        }
    }

    return_integer(result);
}

// module structure declarations
begin_declarations;

begin_struct("behavior");
declare_function("file_open", "r", "i", lisa_behavior_file_open);
declare_function("syscall", "sr", "i", lisa_behavior_syscall);
declare_function("number_of_processes", "", "i", lisa_behavior_number_of_processes);
end_struct("behavior");

begin_struct("network");
declare_function("http_request", "sr", "i", lisa_network_http_request);
declare_function("dns_question", "rs", "i", lisa_network_dns_question);
declare_function("telnet_data", "r", "i", lisa_network_telnet_data);
declare_function("irc", "r", "i", lisa_network_irc);
declare_function("endpoint_ip", "s", "i", lisa_network_endpoint_ip);
declare_function("endpoint_country", "s", "i", lisa_network_endpoint_country);
declare_function("syn_scan", "", "i", lisa_network_syn_scan);
declare_function("blacklisted_ip_access", "", "i", lisa_network_blacklisted_ip_access);
end_struct("network");

end_declarations;

// module initializer
int module_initialize(
    YR_MODULE* module)
{
    return ERROR_SUCCESS;
}

// module finilizer
int module_finalize(
    YR_MODULE* module)
{
    return ERROR_SUCCESS;
}

// loads json data into module structures
int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
    YR_OBJECT* behavior_object;
    YR_OBJECT* network_object;

    json_error_t json_error;
    json_t* json;

    if (module_data == NULL)
        return ERROR_SUCCESS;

    // parse json
    json = json_loadb(
        (const char*)module_data,
        module_data_size,
#if JANSSON_VERSION_HEX >= 0x020600
        JSON_ALLOW_NUL,
#else
        0,
#endif
        &json_error);

    if (json == NULL)
        return ERROR_INVALID_MODULE_DATA;

    module_object->data = (void*)json;

    behavior_object = get_object(module_object, "behavior");
    network_object  = get_object(module_object, "network");

    // load data for modules functions
    behavior_object->data = (void*)json_object_get(json, "dynamic_analysis");
    network_object->data  = (void*)json_object_get(json, "network_analysis");

    return ERROR_SUCCESS;
}

// frees json
int module_unload(YR_OBJECT* module_object)
{
    if (module_object->data != NULL)
        json_decref((json_t*)module_object->data);

    return ERROR_SUCCESS;
}

#undef MODULE_NAME
