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

std::optional<std::string> read_key(const std::string & key_file)
{
    // Read key from file.
    std::ifstream key_stream(key_file, std::ios::binary);
    if (not key_stream)
    {
        return std::nullopt;
    }
    std::stringstream ss;
    ss << key_stream.rdbuf();
    return ss.str();
}

std::tuple<bool, bool> validate(
    const std::string & token,
    const std::string & username,
    const std::string & issuer,
    const std::string & pub_key)
{
    const auto decoded_token = jwt::decode(token);

    // Is the token valid?
    const auto verifier =
        jwt::verify().with_issuer(issuer).allow_algorithm(jwt::algorithm::rs256(pub_key));
    try
    {
        verifier.verify(decoded_token);
    }
    catch (jwt::error::token_verification_exception & exception)
    {
        std::cerr << exception.what() << std::endl;
        return std::make_tuple(false, false);
    }
    auto claims = decoded_token.get_payload_claims();

    // Check username matches.
    if (not claims.contains("upn"))
    {
        std::cerr << "Missing upn." << std::endl;
        return std::make_tuple(false, false);
    }
    if (claims["upn"].as_string() != username)
    {
        std::cerr << "Wrong username." << std::endl;
        return std::make_tuple(false, false);
    }

    // Check for mqtt-write claim value.
    if (not(claims.contains("mqtt-write") and claims.contains("mqtt-read")))
    {
        std::cerr << "Missing mqtt-write or mqtt-read." << std::endl;
        return std::make_tuple(false, false);
    }

    bool can_read = claims["mqtt-read"].as_bool();
    bool can_write = claims["mqtt-write"].as_bool();

    return std::make_tuple(can_read, can_write);
}

std::string gen_token(
    const std::string & issuer,
    const std::string & username,
    const std::string & can_read,
    const std::string & can_write,
    const std::string & pub_key,
    const std::string & priv_key,
    const std::chrono::time_point<std::chrono::system_clock> & expr_time)
{
    const auto token = jwt::create()
                           .set_type("JWT")
                           .set_issuer(issuer)
                           .set_payload_claim("upn", jwt::claim(username))
                           .set_payload_claim("mqtt-read", jwt::claim(can_read))
                           .set_payload_claim("mqtt-write", jwt::claim(can_write))
                           .set_expires_at(expr_time)
                           .sign(jwt::algorithm::rs256(pub_key, priv_key, "", ""));

    return token;
}