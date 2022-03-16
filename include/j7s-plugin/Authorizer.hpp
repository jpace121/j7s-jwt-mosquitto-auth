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
#pragma once

#include <j7s-plugin/AuthList.hpp>

#include <optional>
#include <string>

// Autenticates a user using jwts.
class Authorizer
{
public:
    Authorizer(const std::string& pub_key, const std::string& issuer);
    static std::optional<std::string> read_key(const std::string& key_file);
    void add_unknown(const std::string& username);
    bool is_unknown(const std::string& username);
    bool add(const std::string& token, const std::string& username);
    bool can_read(const std::string& username);
    bool can_write(const std::string& username);
    void logout(const std::string& username);
private:
    AuthList _writeList;
    AuthList _readList;
    AuthList _unknownList;

    std::string _pub_key;
    std::string _issuer;
};
