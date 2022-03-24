# j7s-mosquitto-plugin

Authentication using JWTs for the mosquitto mqtt broker.

## Dependencies
```
sudo apt install mosquitto-dev g++ cmake libmosquitto-dev mosquitto-clients openssl libssl-dev libyaml-cpp-dev
```

## Generating offline keys
```
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

## Converting Client Keys to Format for Browser
```
openssl pkcs12 -export -out client.p12 -inkey client-key.pem -in -client.pem -certfile ca.pem
```
