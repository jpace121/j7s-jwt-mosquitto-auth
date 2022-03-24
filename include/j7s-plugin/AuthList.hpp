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
#include <chrono>
#include <map>
#include <string>

using time_T = std::chrono::time_point<std::chrono::system_clock>;

// A list with easily checkable contents.
class AuthList
{
public:
    AuthList();

    void add(const std::string& username, const time_T& expr_time);
    void remove(const std::string& username);
    bool confirm(const std::string& username);

private:
    std::map<std::string, time_T> _map;
};
