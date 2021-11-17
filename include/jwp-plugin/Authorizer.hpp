#pragma once

#include <string>
#include <jwt-cpp/jwt.h>
#include <jwp-plugin/AuthList.hpp>
#include <optional>

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
