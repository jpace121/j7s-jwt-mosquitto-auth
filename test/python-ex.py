import requests
import json
import time
import jwt

# Get urls.
well_known = requests.get("https://auth.jpace121.net/realms/jpace121-main/.well-known/openid-configuration")
well_known = well_known.json()
auth_url = well_known['device_authorization_endpoint']
token_url = well_known['token_endpoint']

header = {"Content-Type":"application/x-www-form-urlencoded"}
data = {"client_id" : "jpace-mqtt"}

r = requests.post(auth_url, headers=header, data=data)
r_json = r.json()

print("Go to: {} to login.".format(r_json['verification_uri_complete']))

data['grant_type'] = "urn:ietf:params:oauth:grant-type:device_code"
data['device_code'] = r_json['device_code']

for index in range(1, 20):
    r = requests.post(token_url, headers=header, data=data)
    if 'access_token' in r.json():
        break
    time.sleep(r_json['interval'])

public_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlIKdtC04YbRMO0L4ID4YOWLr2AxYpQZYZ3g9BNpVm+IjDdn4H5HaYwYvOcbdjKyRdmwm+rsrIbWxCGYQCD5TtaCnq1IGwOueoprgCTDNSpTxsKQ+JuEUIhKc4rygVhX7JKIvVikfWimKVuNJBVhut/O+/N0AarasszAyinc3gjwtu2SyLBdZtIe3Krs1MIvYb786J2RhK3GfLzrXVzmKjA2/ThB9D6sS7dtZCe//37kYZzGUv5+xFkjkKwZr2aULMlmpUosFd/S2w3zsZkGRELLTvdRf5PVKeGpk40EneETJAHwiMjX6+jO/vlFQIj/Ye66ypVhCCI+NizE/hWbdawIDAQAB\n-----END PUBLIC KEY-----"

#decoded = jwt.decode(r.json()['access_token'], audience=None, options={"verify_signature": False, 'verify_aud': False})
decoded = jwt.decode(r.json()['access_token'], public_key, algorithms=['RS256'])
print('Decoded: {}'.format(decoded))
