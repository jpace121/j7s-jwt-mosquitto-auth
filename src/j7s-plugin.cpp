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
#include <j7s-plugin/j7s-plugin.h>
#include <j7s-plugin/utils.h>

#include <filesystem>
#include <j7s-plugin/Authorizer.hpp>
#include <memory>
#include <string>

// Mosquitto Globals
static mosquitto_plugin_id_t *plugin_id = nullptr;
static std::unique_ptr<Authorizer> authorizer = nullptr;

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
    for (int index = 0; index < supported_version_count; index++)
    {
        if (supported_versions[index] == 5)
        {
            return 5;
        }
    }
    return -1;
}

int mosquitto_plugin_init(
    mosquitto_plugin_id_t *identifier,
    void **userdata,
    struct mosquitto_opt *options,
    int option_count)
{
    plugin_id = identifier;

    if (option_count < 2)
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Missing an option. Found: %d", option_count);
        return MOSQ_ERR_INVAL;
    }

    std::filesystem::path keyFilePath;
    std::filesystem::path aclFilePath;
    for (int index = 0; index < option_count; index++)
    {
        const auto key = std::string(options[index].key);
        if (key == "key_file")
        {
            std::string key_file_string = std::string(options[index].value);
            if (key_file_string.empty())
            {
                mosquitto_log_printf(MOSQ_LOG_ERR, "key_file not set.");
                return MOSQ_ERR_INVAL;
            }
            keyFilePath = std::filesystem::path(key_file_string);
        }
        else if (key == "acl_file")
        {
            std::string acl_file_string = std::string(options[index].value);
            if (acl_file_string.empty())
            {
                mosquitto_log_printf(MOSQ_LOG_ERR, "acl_file not set.");
                return MOSQ_ERR_INVAL;
            }
            aclFilePath = std::filesystem::path(acl_file_string);
        }
    }

    authorizer = std::make_unique<Authorizer>(
        std::filesystem::absolute(keyFilePath).string(),
        std::filesystem::absolute(aclFilePath).string());

    // Register the callbacks.
    mosquitto_callback_register(
        plugin_id, MOSQ_EVT_BASIC_AUTH, j7s_auth_basic_auth_callback, NULL, NULL);
    mosquitto_callback_register(plugin_id, MOSQ_EVT_ACL_CHECK, j7s_acl_check_callback, NULL, NULL);
    mosquitto_callback_register(
        plugin_id, MOSQ_EVT_DISCONNECT, j7s_disconnect_callback, NULL, NULL);
    // May want MOSQ_EVT_RELOAD as well.

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
    if (plugin_id)
    {
        mosquitto_callback_unregister(
            plugin_id, MOSQ_EVT_BASIC_AUTH, j7s_auth_basic_auth_callback, NULL);
        mosquitto_callback_unregister(plugin_id, MOSQ_EVT_ACL_CHECK, j7s_acl_check_callback, NULL);
        mosquitto_callback_unregister(
            plugin_id, MOSQ_EVT_DISCONNECT, j7s_disconnect_callback, NULL);
    }

    return MOSQ_ERR_SUCCESS;
}

int j7s_auth_basic_auth_callback(int event, void *event_data, void *userdata)
{
    if (not authorizer)
    {
        // Not sure this is possible.
        return MOSQ_ERR_AUTH;
    }

    struct mosquitto_evt_basic_auth *auth_data =
        static_cast<struct mosquitto_evt_basic_auth *>(event_data);

    if (!auth_data->username)
    {
        // We need a username to do anything.
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    if (!auth_data->password)
    {
        authorizer->add_unknown(std::string(auth_data->username));
        return MOSQ_ERR_PLUGIN_DEFER;
    }
    bool is_authed =
        authorizer->add(std::string(auth_data->password), std::string(auth_data->username));

    if (is_authed)
    {
        return MOSQ_ERR_SUCCESS;
    }
    else
    {
        return MOSQ_ERR_AUTH;
    }
}

int j7s_acl_check_callback(int event, void *event_data, void *userdata)
{
    if (not authorizer)
    {
        return MOSQ_ERR_ACL_DENIED;
    }

    struct mosquitto_evt_acl_check *acl_data =
        static_cast<struct mosquitto_evt_acl_check *>(event_data);

    const std::string username = std::string(mosquitto_client_username(acl_data->client));

    if (authorizer->is_unknown(username))
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "ACL callback without username");
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    bool success = false;
    switch (acl_data->access)
    {
        case MOSQ_ACL_SUBSCRIBE:
            mosquitto_log_printf(MOSQ_LOG_ERR, "ACL callback subscribe defer.");
            return MOSQ_ERR_PLUGIN_DEFER;
        case MOSQ_ACL_UNSUBSCRIBE:
            mosquitto_log_printf(MOSQ_LOG_ERR, "ACL callback unsubscribe defer.");
            return MOSQ_ERR_PLUGIN_DEFER;
        case MOSQ_ACL_WRITE:
            success = authorizer->can_write(username);
            mosquitto_log_printf(MOSQ_LOG_ERR, "ACL callback %s can write? %d", username.c_str(), success);
            return (authorizer->can_write(username) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
        case MOSQ_ACL_READ:
            success = authorizer->can_read(username);
            mosquitto_log_printf(MOSQ_LOG_ERR, "ACL callback %s can read? %d", username.c_str(), success);
            return (authorizer->can_read(username) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
        default:
            return MOSQ_ERR_ACL_DENIED;
    }
}

int j7s_disconnect_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_disconnect *disconnect_data =
        static_cast<struct mosquitto_evt_disconnect *>(event_data);

    const std::string username = std::string(mosquitto_client_username(disconnect_data->client));

    authorizer->logout(username);
    return MOSQ_ERR_SUCCESS;
}
