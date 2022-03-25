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

// Mosquitto authentication plugin that using Authorizer to authorize
// users using jwts.

extern "C"
{
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
}

// Stuff we're "exporting" for the dynamic loading.
extern "C"
{
    int mosquitto_plugin_version(int supported_version_count, const int *supported_versions);
    int mosquitto_plugin_init(
        mosquitto_plugin_id_t *identifier,
        void **userdata,
        struct mosquitto_opt *options,
        int option_count);
    int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count);
}
// My functions
int j7s_auth_basic_auth_callback(int event, void *event_data, void *userdata);
int j7s_acl_check_callback(int event, void *event_data, void *userdata);
int j7s_disconnect_callback(int event, void *event_data, void *userdata);
