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

#include <argparse/argparse.hpp>
#include <chrono>
#include <filesystem>

int main(int argc, char *argv[])
{
    argparse::ArgumentParser program("gen-token", "0.0.0");

    program.add_argument("--pub-key").required().help("Pub key of signer.");
    program.add_argument("--priv-key").required().help("Private key of signer.");
    program.add_argument("--username").required().help("Username assigned to key.");
    program.add_argument("--valid-days")
        .required()
        .help("Days from now until the token will be valid.");
    program.add_argument("--can-read")
        .help("holder can read")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("--can-write")
        .help("holder can write")
        .default_value(false)
        .implicit_value(true);
    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return -1;
    }

    const auto priv_key_file = program.get<std::string>("--priv-key");
    const auto priv_key = read_key(std::filesystem::absolute(priv_key_file));
    const auto pub_key_file = program.get<std::string>("--pub-key");
    const auto pub_key = read_key(std::filesystem::absolute(pub_key_file));

    if (not pub_key or not priv_key)
    {
        std::cerr << "Could not open key!" << std::endl;
        return -2;
    }

    const std::string can_read = program.get<bool>("--can-read") ? "true" : "false";
    const std::string can_write = program.get<bool>("--can-write") ? "true" : "false";

    const auto now = std::chrono::system_clock::now();
    const auto expr_time =
        now + std::chrono::days(std::stoi(program.get<std::string>("--valid-days")));

    const auto token = gen_token(
        program.get<std::string>("--username"), pub_key.value(), priv_key.value(), now, expr_time);

    std::cout << token;

    return 0;
}
