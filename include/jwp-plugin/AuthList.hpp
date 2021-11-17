#pragma once
#include <forward_list>
#include <string>

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
