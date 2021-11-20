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
#include <jwp-plugin/AuthList.hpp>
#include <algorithm>

AuthList::AuthList():
    _allowedUsernames{}
{
}

void AuthList::add(const std::string& username)
{
    // Is the username already in the list?
    // If not add it.
    if(not confirm(username))
    {
        _allowedUsernames.emplace_front(username);
    }
}

void AuthList::remove(const std::string& username)
{
    // Is the user in the list?
    // Is so, remove it,
    if(confirm(username))
    {
        _allowedUsernames.remove(username);
    }
}

bool AuthList::confirm(const std::string& username)
{
    // Is the user in the list?
    const auto found = std::find(std::begin(_allowedUsernames), std::end(_allowedUsernames), username);
    if(found != std::end(_allowedUsernames))
    {
        return true;
    }
    return false;
}
