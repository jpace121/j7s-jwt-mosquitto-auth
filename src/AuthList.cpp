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
#include <algorithm>
#include <j7s-plugin/AuthList.hpp>

AuthList::AuthList() : _map{} {}

void AuthList::add(const std::string &username, const time_T &login_time)
{
    // Add the user to the list or update it's login time if
    // it's already there.
    _map[username] = login_time;
}

void AuthList::remove(const std::string &username)
{
    // Remove the user
    _map.erase(username);
}

bool AuthList::confirm(const std::string &username)
{
    // Is the user in the map?
    const auto iter = _map.find(username);

    if (iter == _map.end())
    {
        return false;
    }

    return true;
}
