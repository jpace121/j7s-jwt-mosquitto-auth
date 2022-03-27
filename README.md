# j7s-mosquitto-plugin

Authentication using JWTs for the mosquitto mqtt broker.

## Dependencies
```
sudo apt install mosquitto-dev g++ cmake libmosquitto-dev mosquitto-clients openssl libssl-dev libyaml-cpp-dev
```

## Generating offline keys
```
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

## Converting Client Keys to Format for Browser
```
openssl pkcs12 -export -out client.p12 -inkey client-key.pem -in -client.pem -certfile ca.pem
```
