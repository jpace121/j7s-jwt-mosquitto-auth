sudo apt install mosquitto-dev g++ cmake libmosquitto-dev mosquitto-clients

sudo apt install openssl libssl-dev


openssl genpkey -algorithm Ed25519 -out priv.key
openssl pkey -in priv.key -pubout > pub.key
