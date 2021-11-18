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
#include <jwp-plugin/Authorizer.hpp>
#include <jwp-plugin/AuthList.hpp>

#include <jwt-cpp/jwt.h>

#include <iostream>
#include <fstream>
#include <sstream>

Authorizer::Authorizer(const std::string& pub_key, const std::string& issuer):
    _pub_key{pub_key},
    _issuer{issuer}
{
}

std::optional<std::string> Authorizer::read_key(const std::string& key_file)
{
    // Read key from file.
    std::ifstream key_stream(key_file, std::ios::binary);
    if(not key_stream)
    {
        return std::nullopt;
    }
    std::stringstream ss;
    ss << key_stream.rdbuf();
    return ss.str();
}

void Authorizer::add_unknown(const std::string& username)
{
    _unknownList.add(username);
}

bool Authorizer::is_unknown(const std::string& username)
{
    return _unknownList.confirm(username);
}

bool Authorizer::add(const std::string& token, const std::string& username)
{
    const auto decoded_token = jwt::decode(token);

    // Is the token valid?
    const auto verifier = jwt::verify()
        .with_issuer(_issuer)
        .allow_algorithm(jwt::algorithm::rs256(_pub_key));
    try
    {
        verifier.verify(decoded_token);
    }
    catch(jwt::error::token_verification_exception& exception)
    {
        std::cout << exception.what() << std::endl;
        return false;
    }
    auto claims = decoded_token.get_payload_claims();

    // Check username matches.
    if(not claims.contains("upn"))
    {
        std::cout << "Missing upn." << std::endl;
        return false;
    }
    if(claims["upn"].as_string() != username)
    {
        std::cout << "Wrong username." << std::endl;
        return false;
    }

    // Check for mqtt-write claim value.
    if(not (claims.contains("mqtt-write") and claims.contains("mqtt-read")))
    {
        std::cout << "Missing mqtt-write or mqtt-read." << std::endl;
        return false;
    }

    bool can_write = claims["mqtt-write"].as_bool();
    bool can_read = claims["mqtt-read"].as_bool();
    if(not (can_write or can_read))
    {
        std::cout << "Can't write or can't read." << std::endl;
        return false;
    }

    if(can_write)
    {
        _writeList.add(username);
    }
    if(can_read)
    {
        _readList.add(username);
    }

    return true;
}

bool Authorizer::can_read(const std::string& username)
{
    return _readList.confirm(username);
}

bool Authorizer::can_write(const std::string& username)
{
    return _writeList.confirm(username);
}

void Authorizer::logout(const std::string& username)
{
    _writeList.remove(username);
    _readList.remove(username);
    _unknownList.remove(username);
}

