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

#include <chrono>
#include <optional>
#include <string>
#include <tuple>

std::optional<std::string> read_key(const std::string &key_file);

bool validate(const std::string &token, const std::string &username, const std::string &pub_key);

std::string gen_token(
    const std::string &username,
    const std::string &pub_key,
    const std::string &priv_key,
    const std::chrono::time_point<std::chrono::system_clock> &issue_time,
    const std::chrono::time_point<std::chrono::system_clock> &expr_time);
