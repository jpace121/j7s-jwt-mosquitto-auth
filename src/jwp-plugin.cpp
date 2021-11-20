// Copyright 2021 James Pace
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <jwp-plugin/jwp-plugin.h>
#include <jwp-plugin/Authorizer.hpp>
#include <string>
#include <memory>

// Mosquitto Globals
static mosquitto_plugin_id_t *plugin_id = nullptr;
static std::unique_ptr<Authorizer> authorizer = nullptr;

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	for(int index = 0; index < supported_version_count; index++)
    {
		if(supported_versions[index] == 5)
        {
			return 5;
		}
	}
	return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count)
{
    plugin_id = identifier;


    if(option_count != 2)
    {
        return MOSQ_ERR_INVAL;
    }

    std::string public_key;
    std::string issuer;
    for(int index = 0; index < option_count; index++)
    {
        const auto key = std::string(options[index].key);
        if(key == "public_key")
        {
            const auto key = Authorizer::read_key(std::string(options[index].value));
            if(not key or key->empty())
            {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Could not read public key.");
                return MOSQ_ERR_INVAL;
            }
            public_key = *key;
        }
        else if(key == "issuer")
        {
            issuer = std::string(options[index].value);
            if(issuer.empty())
            {
                mosquitto_log_printf(MOSQ_LOG_ERR, "issuer not set.");
                return MOSQ_ERR_INVAL;
            }
        }
    }

    authorizer = std::make_unique<Authorizer>(public_key, issuer);

    // Register the callbacks.
	mosquitto_callback_register(plugin_id, MOSQ_EVT_BASIC_AUTH, jwp_auth_basic_auth_callback, NULL, NULL);
	mosquitto_callback_register(plugin_id, MOSQ_EVT_ACL_CHECK, jwp_acl_check_callback, NULL, NULL);
    mosquitto_callback_register(plugin_id, MOSQ_EVT_DISCONNECT, jwp_disconnect_callback, NULL, NULL);
    // May want MOSQ_EVT_RELOAD as well.

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
    if(plugin_id)
    {
        mosquitto_callback_unregister(plugin_id, MOSQ_EVT_BASIC_AUTH, jwp_auth_basic_auth_callback, NULL);
		mosquitto_callback_unregister(plugin_id, MOSQ_EVT_ACL_CHECK, jwp_acl_check_callback, NULL);
        mosquitto_callback_unregister(plugin_id, MOSQ_EVT_DISCONNECT, jwp_disconnect_callback, NULL);
    }

    return MOSQ_ERR_SUCCESS;
}

int jwp_auth_basic_auth_callback(int event, void *event_data, void *userdata)
{
    if(not authorizer)
    {
        // Not sure this is possible.
        return MOSQ_ERR_AUTH;
    }

    struct mosquitto_evt_basic_auth *auth_data = static_cast<struct mosquitto_evt_basic_auth*>(event_data);

    if(!auth_data->username or !auth_data->password)
    {
        authorizer->add_unknown(std::string(auth_data->username));
        return MOSQ_ERR_PLUGIN_DEFER;
    }
    bool is_authed = authorizer->add(std::string(auth_data->password), std::string(auth_data->username));

    if(is_authed)
    {
        return MOSQ_ERR_SUCCESS;
    }
    else
    {
        return MOSQ_ERR_AUTH;
    }
}

int jwp_acl_check_callback(int event, void *event_data, void *userdata)
{
    if(not authorizer)
    {
        return MOSQ_ERR_ACL_DENIED;
    }

    struct mosquitto_evt_acl_check *acl_data = static_cast<struct mosquitto_evt_acl_check *>(event_data);

    const std::string username = std::string(mosquitto_client_username(acl_data->client));

    if(authorizer->is_unknown(username))
    {
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    switch(acl_data->access)
    {
        case MOSQ_ACL_SUBSCRIBE:
            return MOSQ_ERR_PLUGIN_DEFER;
        case MOSQ_ACL_UNSUBSCRIBE:
            return MOSQ_ERR_PLUGIN_DEFER;
        case MOSQ_ACL_WRITE:
            return (authorizer->can_write(username) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
        case MOSQ_ACL_READ:
            return (authorizer->can_read(username) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
        default:
            return MOSQ_ERR_ACL_DENIED;
    }
}

int jwp_disconnect_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_disconnect *disconnect_data = static_cast<struct mosquitto_evt_disconnect*>(event_data);
    const std::string username = std::string(mosquitto_client_username(disconnect_data->client));

    authorizer->logout(username);
    return MOSQ_ERR_SUCCESS;
}


