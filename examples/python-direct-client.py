import requests
import json
import time
import paho.mqtt.client
import time

s = requests.Session()
s.cert =  ("/home/jimmy/Develop/keycloak/jimmy-client.pem", "/home/jimmy/Develop/keycloak/jimmy-client-key.pem")


# Get urls.
well_known = s.get("https://auth.jpace121.net/realms/jpace121-services/.well-known/openid-configuration", ).json()
token_url = well_known['token_endpoint']
data = {"grant_type" : "password", "client_id" : "mqtt", "username" : "j7s-1"}

# Request token.
r = s.post(token_url, data=data)
print(r.json())
token = r.json()['access_token']

client = paho.mqtt.client.Client(protocol=paho.mqtt.client.MQTTv5,
                                 transport="tcp")
client.username_pw_set("j7s-1", password=token)
client.connect("localhost", port=8081)

print("Waiting on connection.")
time.sleep(5)
