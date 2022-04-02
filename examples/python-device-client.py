import requests
import json
import time
import paho.mqtt.client
import time


# Get urls.
well_known = requests.get("https://auth.jpace121.net/realms/jpace121-main/.well-known/openid-configuration").json()
auth_url = well_known['device_authorization_endpoint']
token_url = well_known['token_endpoint']

header = {"Content-Type":"application/x-www-form-urlencoded"}
data = {"client_id" : "jpace-mqtt"}

# Request login.
r = requests.post(auth_url, headers=header, data=data)
r_json = r.json()
print("Go to: {} to login.".format(r_json['verification_uri_complete']))

# Wait for token.
data['grant_type'] = "urn:ietf:params:oauth:grant-type:device_code"
data['device_code'] = r_json['device_code']
for index in range(1, 20):
    r = requests.post(token_url, headers=header, data=data)
    if 'access_token' in r.json():
        break
    time.sleep(r_json['interval'])

token = r.json()['access_token']
print(token)

client = paho.mqtt.client.Client(protocol=paho.mqtt.client.MQTTv5,
                                 transport="websockets")
client.username_pw_set("jimmy", password=token)
client.tls_set()
client.connect("localhost", port=8082)

print("Waiting on connection.")
time.sleep(20)
