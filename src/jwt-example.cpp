#include <jwt-cpp/jwt.h>
#include <string>
#include <iostream>

int main(int argc, char *argv[])
{
    std::string pub_key = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+IYMWskcPLcC8IsUy6xsj3whqlzYwFWuAmVR7ue/LLw=
-----END PUBLIC KEY-----)";
    std::string priv_key = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID6d/A9UnVV5xXf9RAvXSNTk/a1QNUrzfvawzEAWDh3e
-----END PRIVATE KEY-----)";

    auto token = jwt::create()
        .set_type("JWT")
        .set_issuer("jamesp")
        .set_subject("jimmy")
        .set_audience("mqtt")
        .set_payload_claim("topics", jwt::claim(std::string{"{'/help/*', '/test/*'}"}))
        .set_expires_at(std::chrono::system_clock::now())
        .sign(jwt::algorithm::ed25519(pub_key, priv_key, "", ""));

    std::cout << "Token: " << token << std::endl;

    auto verifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::ed25519(pub_key, "", "", ""))
        .with_issuer("jamesp");

    auto decoded = jwt::decode(token);

    try
    {
        verifier.verify(decoded);
    }
    catch(jwt::error::token_verification_exception& exception)
    {
        std::cout << exception.what() << std::endl;
        return -1;
    }

    for(auto& e : decoded.get_header_claims())
    {
        std::cout << e.first << ": " << e.second.to_json() << std::endl;
    }

    std::cout << std::endl;

    for(auto& e : decoded.get_payload_claims())
    {
        std::cout << e.first << ": " << e.second.to_json() << std::endl;
    }

    return 0;
}

