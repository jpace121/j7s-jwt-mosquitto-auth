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
#include <forward_list>
#include <string>

// A list with easily checkable contents.
class AuthList
{
public:
    AuthList();

    void add(const std::string& username);
    void remove(const std::string& username);
    bool confirm(const std::string& username);

private:
    std::forward_list<std::string> _allowedUsernames;
};
