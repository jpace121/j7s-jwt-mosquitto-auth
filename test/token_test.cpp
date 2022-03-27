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

#include <iostream>

#include "gtest/gtest.h"

const std::string priv_key_a =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDBUDCgCQBYv0gfDoEg8366jUkUCpsfPhCM751mhkPc6oAoGCCqGSM49
AwEHoUQDQgAE4RR0GJUrETmm9qgTMhvrgqDyQrbyrwJvkQCWTf7vpRM9gBt6BWzO
uIMX39ic8T1m+SHWmwECtSwDUNN7unaJyA==
-----END EC PRIVATE KEY-----)";
const std::string pub_key_a =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4RR0GJUrETmm9qgTMhvrgqDyQrby
rwJvkQCWTf7vpRM9gBt6BWzOuIMX39ic8T1m+SHWmwECtSwDUNN7unaJyA==
-----END PUBLIC KEY-----)";

const std::string priv_key_b =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFBc4fpIgmZAuQJobeCxN+51C4V33FbW3hOoB8ycXbJsoAoGCCqGSM49
AwEHoUQDQgAErkFbtgVLcHVN0dj9E6apaP9GEYl+i9lSL6Y9VQPfOOt8vl7T9WUv
qG+iL+euugvvsKyPEOBjmWxlyQZUoVevhg==
-----END EC PRIVATE KEY-----)";
const std::string pub_key_b =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErkFbtgVLcHVN0dj9E6apaP9GEYl+
i9lSL6Y9VQPfOOt8vl7T9WUvqG+iL+euugvvsKyPEOBjmWxlyQZUoVevhg==
-----END PUBLIC KEY-----)";

using time_T = std::chrono::time_point<std::chrono::system_clock>;

TEST(TokenTest, SimpleTwoWay)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);

    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const bool valid = validate(token, username, pub_key_a);

    EXPECT_TRUE(valid);
}

TEST(TokenTest, SimpleTwoWayWithOtherKey)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);

    const auto token = gen_token(username, pub_key_b, priv_key_b, now, expire);

    const bool valid = validate(token, username, pub_key_b);

    EXPECT_TRUE(valid);
}

TEST(TokenTest, InvalidUsername)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const std::string notjames = "not_james";
    const bool valid = validate(token, notjames, pub_key_a);

    EXPECT_FALSE(valid);
}

TEST(TokenTest, WrongKey)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const bool valid = validate(token, username, pub_key_b);

    EXPECT_FALSE(valid);
}

TEST(TokenTest, NonsenseKey)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const std::string nonsenseKey = "lslslslsl";

    const bool valid = validate(token, username, nonsenseKey);

    EXPECT_FALSE(valid);
}
