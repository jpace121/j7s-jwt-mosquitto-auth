import requests
import json
import time
import paho.mqtt.client
import time

# RESULT=`curl --cacert ./ca.pem  --cert jimmy-client.pem --key jimmy-client-key.pem --data "grant_type=password&client_id=test&username=jimmy&password=1234" https://nginx-test.internal.jpace121.net:8443/realms/master/protocol/openid-connect/token`

s = requests.Session()
s.verify = "/home/jimmy/Develop/mosquitto-plugin/test/ca.pem"
s.cert =  ("/home/jimmy/Develop/keycloak/jimmy-client.pem", "/home/jimmy/Develop/keycloak/jimmy-client-key.pem")


# Get urls.
print("Before get.")
well_known = s.get("https://nginx-test.internal.jpace121.net:8443/realms/jpace121-main/.well-known/openid-configuration", ).json()
print("After get.")
token_url = well_known['token_endpoint']
# Override for now, url doesn't include port...
token_url = "https://nginx-test.internal.jpace121.net:8443/realms/jpace121-main/protocol/openid-connect/token"
# RESULT=`curl --cacert ./ca.pem  --cert jimmy-client.pem --key jimmy-client-key.pem --data "grant_type=password&client_id=mqtt&username=jimmy&password=1234" https://nginx-test.internal.jpace121.net:8443/realms/jpace121-main/protocol/openid-connect/token`


data = {"grant_type" : "password", "client_id" : "mqtt", "username" : "jimmy", "password": "1234"}

# Request token.
r = s.post(token_url, data=data)
token = r.json()['access_token']

client = paho.mqtt.client.Client(protocol=paho.mqtt.client.MQTTv5,
                                 transport="tcp")
client.username_pw_set("jimmy", password=token)
client.connect("localhost", port=8081)

print("Waiting on connection.")
time.sleep(20)
