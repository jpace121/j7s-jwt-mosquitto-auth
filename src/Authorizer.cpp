// Copyright 2021-2022 James Pace
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

#include <filesystem>
#include <iostream>
#include <j7s-plugin/AuthList.hpp>
#include <j7s-plugin/Authorizer.hpp>
#include <tuple>
#include <vector>

// Util.
std::tuple<bool, bool> checkACL(const std::string &user, const YAML::Node &aclFile);
std::vector<std::string> getKey(const std::string &user, const YAML::Node &keyFile);

// Class implementation.
Authorizer::Authorizer(const std::string &keyFilePath, const std::string &aclFilePath) :
    _keyFile{YAML::LoadFile(keyFilePath)}, _aclFile{YAML::LoadFile(aclFilePath)}
{
}

bool Authorizer::add(const std::string &token, const std::string &username)
{
    // We should protect from this already.
    if (token.empty() or username.empty())
    {
        return false;
    }

    const auto keys = getKey(username, _keyFile);

    // Do any of the keys validate the token?
    const bool validated = [token, username, keys]() {
        for (const auto key : keys)
        {
            if (validate(token, username, key))
            {
                return true;
            }
        }
        return false;
    }();

    if (not validated)
    {
        std::cerr << "Not validated." << std::endl;
        return false;
    }

    // Check the ACL file.
    const auto [can_read, can_write] = checkACL(username, _aclFile);

    if (can_read)
    {
        _readList.add(username, std::chrono::system_clock::now());
    }
    if (can_write)
    {
        _writeList.add(username, std::chrono::system_clock::now());
    }

    return true;
}

bool Authorizer::can_read(const std::string &username)
{
    return _readList.confirm(username);
}

bool Authorizer::can_write(const std::string &username)
{
    return _writeList.confirm(username);
}

void Authorizer::logout(const std::string &username)
{
    _writeList.remove(username);
    _readList.remove(username);
    _unknownList.remove(username);
}

void Authorizer::add_unknown(const std::string &username)
{
    _unknownList.add(username, std::chrono::system_clock::now());
}

bool Authorizer::is_unknown(const std::string &username)
{
    return (username.empty() or _unknownList.confirm(username));
}

// Util.
std::tuple<bool, bool> checkACL(const std::string &user, const YAML::Node &aclFile)
{
    // TODO: Make sure default exists.

    YAML::Node userDict;
    if (aclFile[user])
    {
        userDict = aclFile[user];
    }
    else
    {
        userDict = aclFile["default"];
    }

    bool can_read = false;
    bool can_write = false;
    if (userDict["can_read"] and userDict["can_read"].as<bool>())
    {
        can_read = true;
    }
    if (userDict["can_write"] and userDict["can_write"].as<bool>())
    {
        can_write = true;
    }

    return std::make_tuple(can_read, can_write);
}

std::vector<std::string> getKey(const std::string &user, const YAML::Node &keyFile)
{

    // Find this user's entry or the default one.
    YAML::Node userKey;
    if(keyFile[user])
    {
        userKey = keyFile[user];
    }
    else
    {
        // TODO: Make sure default exists.
        userKey = keyFile["default"];
    }

    // Get the paths from the yaml file as std::filesystem::paths.
    std::vector<std::filesystem::path> paths;
    if(not userKey.IsSequence())
    {
        paths.emplace_back(userKey.as<std::string>());
    }
    else
    {
        for(const auto key : userKey)
        {
            paths.emplace_back(key.as<std::string>());
        }
    }

    // Now convert to an array of optional keys.
    std::vector<std::string> keys;
    for(const auto path : paths)
    {
        const auto key = read_key(std::filesystem::absolute(path).string());
        if(key)
        {
            keys.emplace_back(key.value());
        }
    }

    return keys;
}
