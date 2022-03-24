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
#include <j7s-plugin/utils.h>

#include <iostream>
#include <j7s-plugin/AuthList.hpp>
#include <j7s-plugin/Authorizer.hpp>

#include <tuple>

// Util.
std::tuple<bool, bool> checkACL(const YAML::Node& user);

// Class implementation.
Authorizer::Authorizer(
    const std::string & pub_key, const std::string & issuer, const std::string & aclFilePath) :
    _pub_key{pub_key}, _issuer{issuer}, _aclFile{aclFilePath}
{
}

void Authorizer::add_unknown(const std::string & username)
{
    _unknownList.add(username, time_T::max());
}

bool Authorizer::is_unknown(const std::string & username)
{
    return (username.empty() or _unknownList.confirm(username));
}

bool Authorizer::add(const std::string & token, const std::string & username)
{
    const auto [validated, expr_time] = validate(token, username, _issuer, _pub_key);
    if (not validated)
    {
        std::cerr << "Not validated." << std::endl;
        return false;
    }

    // Check the ACL file.
    // TODO: Make sure default is in ACL file.
    if (not _aclFile[username])
    {
        const auto checkACL(_aclFile["default"]);
        return true;
    }
    const auto [can_read, can_write] = checkACL(_aclFile[username]);

    if (can_read)
    {
        _readList.add(username, expr_time);
    }
    if (can_write)
    {
        _writeList.add(username, expr_time);
    }

    return true;
}


bool Authorizer::can_read(const std::string & username)
{
    return _readList.confirm(username);
}

bool Authorizer::can_write(const std::string & username)
{
    return _writeList.confirm(username);
}

void Authorizer::logout(const std::string & username)
{
    _writeList.remove(username);
    _readList.remove(username);
    _unknownList.remove(username);
}

// Util.
std::tuple<bool, bool> checkACL(const YAML::Node& user)
{
    bool can_read = false;
    bool can_write = false;
    if(user["can_read"] and user["can_read"].as<bool>())
    {
        can_read = true;
    }
    if(user["can_write"] and user["can_write"].as<bool>())
    {
        can_write = true;
    }

    return std::make_tuple(can_read, can_write);
}
