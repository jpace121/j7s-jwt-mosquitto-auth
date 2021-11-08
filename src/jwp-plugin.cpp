extern "C" {
    #include "mosquitto.h"
    #include "mosquitto_broker.h"
    #include "mosquitto_plugin.h"
}
#include <string>

// Stuff we're "exporting" for the dynamic loading.
extern "C" {
    int mosquitto_plugin_version(int supported_version_count, const int *supported_versions);
    int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count);
    int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count);
}
// My functions
int jwp_auth_basic_auth_callback(int event, void *event_data, void *userdata);
int jwp_acl_check_callback(int event, void *event_data, void *userdata);


// Mosquitto Globals
static mosquitto_plugin_id_t *plugin_id = nullptr;


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

	mosquitto_callback_register(plugin_id, MOSQ_EVT_BASIC_AUTH, jwp_auth_basic_auth_callback, NULL, NULL);
	mosquitto_callback_register(plugin_id, MOSQ_EVT_ACL_CHECK, jwp_acl_check_callback, NULL, NULL);
    // May want MOSQ_EVT_RELOAD as well.

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
    if(plugin_id)
    {
        mosquitto_callback_unregister(plugin_id, MOSQ_EVT_BASIC_AUTH, jwp_auth_basic_auth_callback, NULL);
		mosquitto_callback_unregister(plugin_id, MOSQ_EVT_ACL_CHECK, jwp_acl_check_callback, NULL);
    }

    return MOSQ_ERR_SUCCESS;
}

int jwp_auth_basic_auth_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_basic_auth *auth_data = static_cast<struct mosquitto_evt_basic_auth*>(event_data);

    if(!auth_data->username or !auth_data->password)
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "No username or password.");
        return MOSQ_ERR_PLUGIN_DEFER;
    }
    mosquitto_log_printf(MOSQ_LOG_ERR, "Username: %s Password: %s",
                         auth_data->username, auth_data->password);

    return MOSQ_ERR_SUCCESS; // MOSQ_ERR_AUTH;
}

int jwp_acl_check_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_acl_check *acl_data = static_cast<struct mosquitto_evt_acl_check *>(event_data);

    std::string event_name = "none";
    switch(acl_data->access)
    {
        case MOSQ_ACL_SUBSCRIBE:
            event_name = "subscribe";
            break;
        case MOSQ_ACL_UNSUBSCRIBE:
            event_name = "unsubscribe";
            break;
        case MOSQ_ACL_WRITE:
            event_name = "write";
            break;
        case MOSQ_ACL_READ:
            event_name = "read";
            break;
    }

    mosquitto_log_printf(MOSQ_LOG_ERR, "Topic: %s Event: %s",
                         acl_data->topic, event_name.c_str());

    return MOSQ_ERR_SUCCESS; // MOSQ_ERR_ACL_DENIED;

}


