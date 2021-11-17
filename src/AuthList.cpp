#include <algorithm>
#include <jwp-plugin/AuthList.hpp>

AuthList::AuthList():
    _allowedUsernames{}
{
}

void AuthList::add(const std::string& username)
{
    // Is the username already in the list?
    // If not add it.
    const auto found = std::find(std::begin(_allowedUsernames), std::end(_allowedUsernames), username);
    if(found == std::end(_allowedUsernames))
    {
        _allowedUsernames.emplace_front(username);
    }
}

void AuthList::remove(const std::string& username)
{
    const auto found = std::find(std::begin(_allowedUsernames), std::end(_allowedUsernames), username);
    if(found != std::end(_allowedUsernames))
    {
        _allowedUsernames.remove(username);
    }
}

bool AuthList::confirm(const std::string& username)
{
    const auto found = std::find(std::begin(_allowedUsernames), std::end(_allowedUsernames), username);
    if(found != std::end(_allowedUsernames))
    {
        return true;
    }
    return false;
}
