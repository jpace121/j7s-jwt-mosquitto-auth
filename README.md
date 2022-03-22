# j7s-mosquitto-plugin

Authentication using JWTs for the mosquitto mqtt broker.

## Dependencies
```
sudo apt install mosquitto-dev g++ cmake libmosquitto-dev mosquitto-clients openssl libssl-dev
```

## Generating offline keys
ssh-keygen -t rsa -b 4096 -m PEM -f priv.key
rm priv.key.pub
openssl rsa -in priv.key -pubout -outform PEM -out pub.key
