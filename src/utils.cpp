// Copyright 2022 James Pace
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
#include <jwt-cpp/jwt.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>

std::optional<std::string> read_key(const std::string &key_file)
{
    // Read key from file.
    std::ifstream key_stream(key_file, std::ios::binary);
    if (not key_stream)
    {
        return std::nullopt;
    }
    std::stringstream ss;
    ss << key_stream.rdbuf();
    const std::string key(ss.str());
    if (key.empty())
    {
        return std::nullopt;
    }

    return key;
}

bool validate(const std::string &token, const std::string &username, const std::string &pub_key)
{
    if (token.empty() or username.empty() or pub_key.empty())
    {
        return false;
    }

    const auto decoded_token = jwt::decode(token);

    try
    {
        // Is the token valid?
        const auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::es256(pub_key));
        verifier.verify(decoded_token);
    }
    catch (std::system_error &exception)
    {
        return false;
    }
    auto claims = decoded_token.get_payload_claims();

    try
    {
        // Check username matches.
        if (not claims.contains("upn"))
        {
            std::cerr << "Missing upn." << std::endl;
            return false;
        }
        if (claims["upn"].as_string() != username)
        {
            std::cerr << "Wrong username." << std::endl;
            return false;
        }

        // Check for mqtt-write claim value.
        if (not claims.contains("mqtt"))
        {
            std::cerr << "Missing mqtt claim." << std::endl;
            return false;
        }
        if (not(claims["mqtt"].as_bool()))
        {
            std::cerr << "Not claiming can do mqtt." << std::endl;
            return false;
        }

        // Do we have an expiration time?
        if (not claims.contains("exp"))
        {
            std::cerr << "Missing expiration time claim." << std::endl;
            return false;
        }
    }
    catch(const std::bad_cast& exception)
    {
        std::cerr << "Failed to parse claims. Reason: " << exception.what()  << std::endl;
        return false;
    }

    return true;
}

std::string gen_token(
    const std::string &username,
    const std::string &pub_key,
    const std::string &priv_key,
    const std::chrono::time_point<std::chrono::system_clock> &issue_time,
    const std::chrono::time_point<std::chrono::system_clock> &expr_time)
{
    const auto token = jwt::create()
                           .set_type("JWT")
                           .set_payload_claim("upn", jwt::claim(username))
                           .set_payload_claim("mqtt", jwt::claim(picojson::value(true)))
                           .set_issued_at(issue_time)
                           .set_expires_at(expr_time)
                           .sign(jwt::algorithm::es256(pub_key, priv_key, "", ""));

    return token;
}

std::string toString(const char* c_str)
{
    if(c_str)
    {
        return std::string(c_str);
    }
    else
    {
        return std::string();
    }
}
