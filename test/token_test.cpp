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

#include <ctime>
#include <iostream>

#include "gtest/gtest.h"

const std::string priv_key_a =
    R"(-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC+ouwDpYOWDEyM
nJhwejOn+boDxw4ntiOR3kRzIANuJrbEPf3UJFL+SPPzzY7NU1A6XPz/NAccbvfn
c78dj12rsV6st5GuFx9QbxYn2XQb8vnxj+DhvSrNk+qy7IMaN/3NGrAoWemSIRIW
VB7xbVybQyvAucgaTDKnU72viNOxqg8v5bGF+WtTjKwezmYtyQ8Z7dpGQbML1tkT
EQwTq5nnLre8F/t6fTS4ziGVw7STggSroAHazphzYmqc3W68jY/SQefOilALwzFp
/Cxoubj0d+f3OYT5jnfMPSpKJiYNlLqxCJPGjNcSRxjzzRt/cRYzhAPfriO/fkYG
tQcLNB5dAgMBAAECggEAd+qyPeT6rgNUj8rdlTs5jTtoiIHJZK+NFm/TbPvBTKPr
qew45B5pWm13j3BJmN0EhYIC32HR60/ef2hu2uBZEuyC2nCqofEHkKggLrb5867X
DN3tnvJIn4KhSyW9nluEOmXEU82jQHmvD/6gbEvXyg7p0dTLi8dMwbbKhkWyrHlu
lqvuJUvdDFv9X2k/y440cKhyssP5HlR/sXn+za5XQoPEtZIh9xM9sg0slSIq+eu1
FRKS0Geo8e93L31jXn1GoNTSCIupyj3EZiKGE0xhxTmjoO+dEEVg6gTdYNAQd6Nx
aaMdLRNo2hfk7ATA+L3hcfFSM+3QPg7wFCInGHQF/QKBgQD1aQ+GX6vl3lmZs+TX
6Hp7qtL6g+TJ2/fSXqbMURHBtdTFFzROqtzIAHwp30fGCGG9reAmRZVHv2mF7U49
3qk9/TcK4nUsGq/o87RKjmrUmLrEx1mtJK10BuJW2lEPIBG6Ws9tGAwSzhs5Lw5H
LnbQHD4dftjhqhNX8ZoU5oG7dwKBgQDG3MwqaMQ55sh8+ci6tZ4pOm1/8Lin0gyh
iNFa8UxFkTsaLHnDXrsUJCkqRwtNtV4Fhbv7x+4smGxDzuJkF6U7uxONJgWp1qlW
6B0SBgKUPdxeGJYG4+ww9qsapARZzZ/1GLYv47+kPs0slz+A0OHeNs1BKhGJLK23
P88MSG8BywKBgFnLs26Lmy5lCYwAEwAdhJOzkbcwg4qI/kjvcUDZeRHUIqJrNyyB
wH8+DjCUDoMblgf9k0Ltuw2hsE7c4gApdOvFt1o4On+E1FD8uz98lQJtUAmol9uO
zBjkW/VDtN0/8rypdbSJVAGdgMCPwz2wdrD3ZJMOUvVfcex/7s0u+tFJAoGAJoPb
ExepcaFuES57nxXP5SJI1O+1g+NdyOdrzNZRNGQVc1NL3ff5+cOrKWILIWjQJfep
2fD2AzMePN/T3xjpSrFH7x1/GU7XC1r3TmdVloqIpLzUSc9ZDn6n0wgTQ6Vcpqa7
mnjcxB3ZtRoyFWvfYx9wD3/rV4sMtiIoorNgtJMCgYABDGH571InLE9HMO1+Czmp
zyvcbTAq8GiN0G4Rok95+THfa726N6BcmkZUK1xWaleO6xNGrDsBghfmgw629Ujk
UJ73ERYyATbA4GHM9f3dbje8pd2SFa4xF+0Xp09qY380aJrZSWsklBZPUmYiU6+W
i2MlHfF+44rBO9igkUjQKA==
-----END PRIVATE KEY-----)";
const std::string pub_key_a =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvqLsA6WDlgxMjJyYcHoz
p/m6A8cOJ7Yjkd5EcyADbia2xD391CRS/kjz882OzVNQOlz8/zQHHG7353O/HY9d
q7FerLeRrhcfUG8WJ9l0G/L58Y/g4b0qzZPqsuyDGjf9zRqwKFnpkiESFlQe8W1c
m0MrwLnIGkwyp1O9r4jTsaoPL+WxhflrU4ysHs5mLckPGe3aRkGzC9bZExEME6uZ
5y63vBf7en00uM4hlcO0k4IEq6AB2s6Yc2JqnN1uvI2P0kHnzopQC8MxafwsaLm4
9Hfn9zmE+Y53zD0qSiYmDZS6sQiTxozXEkcY880bf3EWM4QD364jv35GBrUHCzQe
XQIDAQAB
-----END PUBLIC KEY-----)";

const std::string priv_key_b =
    R"(-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYq8QNOXZRoAid
R7cKE9byr+9WekPMNDNkaKTjRUoXj8lUgno3y5tIDEIqhcv4thTLAxzQD4N+bVA3
XF1ZMfm2GmM0O61AtpKwL6diBeGpCTunwzl9nrTeackQmwqRwllc3kW/npudNn12
M9m4wsgLK98juyY6pZAeTlAvmVkMnFGoyv60jQciWvCFSYkpv2zxAOrmiCjgeYhU
+d8B64qqWmnvdeLl8XGdBYN6nz+vWtWNDi/YuoGI2qhcuiikKvk0Ofmxx3+s4NHS
DqdFfv3CbA5BFBLaHnFHVn+jocEgafOWUjruYcwrUcZuCr8Oy8KLqz6w5Xta/B7x
0Lyx3zvHAgMBAAECggEADQw5ACxWCVnVAqQbZ5gUeb9BhDGE09HuRnmPBgFo+KSI
P1m7WkNjbP/nM70llobxNfx5HOsGgOqUvXZ+X94eikqtCczD3ND9rmMUOhNomsq4
N3k+05aZvJxr26h0ecqTWpWAfoTupbv/cvexdtHmyNWiB2q6NK7rpztoLPk9HA+q
OzVH/qFbtqr1cQJijyrow97A/Yi2f3Kvp7irlLbH0QxxF9jPW/KDn2FIzycoFUtq
NfuXkUpRkVA82lOyL80uYfQmNkM5/nKJxCTdUtSvA58a2jUC8xVH372kSKikTh6o
clIR8vnvp2aFOrlyz3WfZGZgTo8/MuXP69aujwNgQQKBgQDItvqbcmHjWLIEuheS
ahwIlFFhRR24ytsoRm1HVytBa+tmm56WjPV4chutrEz6IjPd8AvICwpQfCu17iUn
7HM5a0hMctFtVxYuHGnMszD1KpgEByPnv59pPnTbvhqlnRpNR1aM2KVxAXAKSOgY
8u+FA3c4wgUpA3z0l7Db33CUJwKBgQDCuRG8+8+HbQdMmct2+YbId/LSyvnoa9uS
LYXn0WboCOZkEv0KxTjfn2wuLn0WaGG44ucvaFE4hDa7d6cIgrpBLD04rS8xSwa7
uEQeRrThIn7Gv/RpcTxk0TASIEN2zIi18OV0Wx92wTTv34omFxZLPit9UgiCJM7i
nAFUD6K/YQKBgC33geNRyctIR9S/TaCxfmQUm6KcMpdcld5eaq547yYXchzYrPQr
qhgAggg/Oo3agWhljj0tEhqmpVgQByBijWzr/e3MKdxRonnC9hP0QdUUASaDAB0W
DIsMy7R7kBy3owtpuA+fmhwMST2Bvu3fzSz4QziTbp0a+GYHy3A/dsfnAoGAPYiK
SHQyopMbqWM4XsJ/iz4MZ/xoeMAMxObJ1/XeVRjq5VjyycKFNHWGlBlwwfH+X5Sk
heCrOfbd7OPkztWw0gOO3SgtL6CL4iparE6fvj1OXrQuIlv8P8ezLycu6o277fLQ
L7LUAI0Rk3PKjjrheqmMyK9xrN7A2e9+o/fE8EECgYAx3IziYqFfD4KzgmcM6MKx
t4/SVFXBRLzse8AB3V6qSEwgCaUfeuj0Qq93nrkTIodHFWXuFoQTgQrA29VWbK6x
PSwjdVNwYES+Hg+LbXP8Fo+u5sGhcWLzWdmFp3UdUm5Mv76Oo+MriZNnS4RQiX0+
Y8PiIt3YYCsowmchtEggaQ==
-----END PRIVATE KEY-----)";
const std::string pub_key_b =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmKvEDTl2UaAInUe3ChPW
8q/vVnpDzDQzZGik40VKF4/JVIJ6N8ubSAxCKoXL+LYUywMc0A+Dfm1QN1xdWTH5
thpjNDutQLaSsC+nYgXhqQk7p8M5fZ603mnJEJsKkcJZXN5Fv56bnTZ9djPZuMLI
CyvfI7smOqWQHk5QL5lZDJxRqMr+tI0HIlrwhUmJKb9s8QDq5ogo4HmIVPnfAeuK
qlpp73Xi5fFxnQWDep8/r1rVjQ4v2LqBiNqoXLoopCr5NDn5scd/rODR0g6nRX79
wmwOQRQS2h5xR1Z/o6HBIGnzllI67mHMK1HGbgq/DsvCi6s+sOV7Wvwe8dC8sd87
xwIDAQAB
-----END PUBLIC KEY-----)";

using time_T = std::chrono::time_point<std::chrono::system_clock>;

TEST(TokenTest, SimpleTwoWay)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);

    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    auto [valid, end] = validate(token, username, pub_key_a);

    std::time_t expire_time = std::chrono::system_clock::to_time_t(expire);
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    EXPECT_TRUE(valid);
    EXPECT_EQ(end_time, expire_time);
}

TEST(TokenTest, InvalidUsername)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const std::string notjames = "not_james";
    const auto [valid, end] = validate(token, notjames, pub_key_a);

    EXPECT_FALSE(valid);
}

TEST(TokenTest, WrongKey)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const auto [valid, end] = validate(token, username, pub_key_b);

    EXPECT_FALSE(valid);
}

TEST(TokenTest, NonsenseKey)
{
    const std::string username = "james";
    const time_T now = std::chrono::system_clock::now();
    const time_T expire = now + std::chrono::seconds(1);
    const auto token = gen_token(username, pub_key_a, priv_key_a, now, expire);

    const std::string nonsenseKey = "lslslslsl";

    const auto [valid, end] = validate(token, username, nonsenseKey);

    EXPECT_FALSE(valid);
}
