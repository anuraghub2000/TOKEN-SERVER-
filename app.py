from flask import Flask, render_template, request, jsonify
import requests
import uuid
import time
import base64
import io
import struct
import random
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

app = Flask(__name__, template_folder='templates')

# --- CONFIGURATION ---
FB_APP_ID = "350685531728"
FB_APP_SECRET = "62f8ce9f74b12f84c123cc23437a4a32"
LITE_APP_ID = "275254692598279"
API_GRAPH = "https://b-graph.facebook.com"

# ==========================================
# ENCRYPTION (Password ko secure karne ke liye)
# ==========================================
class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key():
        try:
            url = f'{API_GRAPH}/pwd_key_fetch'
            params = {
                'version': '2', 'flow': 'CONTROLLER_INITIALIZATION', 'method': 'GET',
                'fb_api_req_friendly_name': 'pwdKeyFetch', 'access_token': f'{FB_APP_ID}|{FB_APP_SECRET}'
            }
            response = requests.post(url, params=params, timeout=10).json()
            return response.get('public_key'), str(response.get('key_id', '25'))
        except Exception:
            return None, "25"

    @staticmethod
    def encrypt(password, public_key=None, key_id="25"):
        if public_key is None:
            public_key, key_id = FacebookPasswordEncryptor.get_public_key()
            if public_key is None: raise Exception("Key fetch failed")
        try:
            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode("utf-8"))
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))
            
            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)
            return f"#PWD_FB4A:2:{current_time}:{base64.b64encode(buf.getvalue()).decode('utf-8')}"
        except Exception as e:
            raise e

# ==========================================
# DEVICE SIMULATION
# ==========================================
class DeviceFingerprint:
    def __init__(self):
        self.device_id = str(uuid.uuid4())
        self.family_device_id = str(uuid.uuid4())
        self.adid = str(uuid.uuid4())
        self.os_version = "13"
        self.device_model = "Pixel 8 Pro"
        self.device_build = "TQ3A.221210.004"
        self.device_brand = "Google"
        self.locale = "en_US"
        self.fbav = "525.0.0.45.105"
        self.fbbv = "650000000"
        
        self.user_agent = (
            f"Dalvik/2.1.0 (Linux; U; Android {self.os_version}; {self.device_model} Build/{self.device_build}) "
            f"[FBAN/FB4A;FBAV/{self.fbav};FBPN/com.facebook.katana;FBLC/{self.locale};FBBV/{self.fbbv};"
            f"FBCR/Verizon;FBMF/{self.device_brand};FBBD/{self.device_brand};FBDV/{self.device_model};"
            f"FBSV/{self.os_version};FBCA/arm64-v8a:null;FBDM/density=480,width=1344,height=1920;"
            f"FB_FW/1;FBRV/0;]"
        )

    def get_headers(self):
        return {
            "User-Agent": self.user_agent, "X-FB-Connection-Quality": "EXCELLENT",
            "X-FB-Connection-Type": "WIFI", "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded", "X-FB-Friendly-Name": "authenticate"
        }

    def get_base_params(self):
        return {
            "device_id": self.device_id, "family_device_id": self.family_device_id, "adid": self.adid,
            "format": "json", "credentials_type": "password", "source": "login",
            "generate_session_cookies": "1", "generate_machine_id": "1", "currently_logged_in_userid": "0",
            "fb_api_req_friendly_name": "authenticate", "fb_api_caller_class": "com.facebook.auth.login.AuthOperations",
            "platform": "android", "api_key": FB_APP_ID
        }

# ==========================================
# SESSIONS & HELPERS
# ==========================================
sessions = {}
recover_sessions = {}

def human_delay(min_s=0.3, max_s=0.8):
    time.sleep(random.uniform(min_s, max_s))

def internal_login(uid, raw_password, device, session):
    try:
        pub_key, key_id = FacebookPasswordEncryptor.get_public_key()
        enc_pw = FacebookPasswordEncryptor.encrypt(raw_password, pub_key, key_id)
        data = device.get_base_params()
        data.update({"email": uid, "password": enc_pw})
        
        res = session.post(f"{API_GRAPH}/auth/login", data=data, timeout=15).json()
        if 'access_token' in res: return res['access_token']
        return None
    except:
        return None

# ==========================================
# ROUTES
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

# 1. NORMAL LOGIN (With 2FA Detection)
@app.route('/api/login', methods=['POST'])
def login():
    uid = request.json.get('username')
    password = request.json.get('password')
    
    if not uid or not password: return jsonify({'error': 'Missing fields'})

    device = DeviceFingerprint()
    session = requests.Session()
    session.headers.update(device.get_headers())

    try:
        pub_key, key_id = FacebookPasswordEncryptor.get_public_key()
        enc_pw = FacebookPasswordEncryptor.encrypt(password, pub_key, key_id)
        data = device.get_base_params()
        data.update({"email": uid, "password": enc_pw})

        human_delay()
        res = session.post(f"{API_GRAPH}/auth/login", data=data, timeout=15).json()

        if 'access_token' in res:
            return jsonify({'status': 'success', 'token': res['access_token']})

        if 'error' in res:
            err = res['error']
            err_data = err.get('error_data', {})
            # Check for 2FA / Notification Approval
            if err.get('code') in [317, 459] or 'login_first_factor' in err_data:
                session_id = str(uuid.uuid4())
                sessions[session_id] = {
                    'uid': uid, 'device': device, 'session': session, 
                    'data': data, 'err_data': err_data
                }
                is_approval = 'login_first_factor' in err_data
                return jsonify({
                    'status': 'challenge', 
                    'session_id': session_id,
                    'type': 'approval' if is_approval else 'otp'
                })
            return jsonify({'status': 'error', 'message': err.get('message')})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 2. APPROVAL POLLING (Wait for Yes/No)
@app.route('/api/poll_approval', methods=['POST'])
def poll_approval():
    session_id = request.json.get('session_id')
    if session_id not in sessions: return jsonify({'status': 'error', 'message': 'Session expired'})
    
    s = sessions[session_id]
    data, err_data = s['data'], s['err_data']
    
    data['credentials_type'] = 'two_factor'
    if 'uid' in err_data: data['userid'] = err_data['uid']
    if 'login_first_factor' in err_data:
        data['first_factor'] = err_data['login_first_factor']
        data['machine_id'] = err_data.get('machine_id', s['device'].device_id)

    try:
        res = s['session'].post(f"{API_GRAPH}/auth/login", data=data, timeout=15).json()
        
        if 'access_token' in res:
            del sessions[session_id]
            return jsonify({'status': 'success', 'token': res['access_token']})
            
        if 'error' in res:
            if res['error'].get('code') in [317, 459, 1348136]:
                return jsonify({'status': 'waiting'}) # Still waiting for user to click Yes
            return jsonify({'status': 'error', 'message': res['error'].get('message')})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 3. OTP VERIFICATION
@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    session_id = request.json.get('session_id')
    otp = request.json.get('otp')
    if session_id not in sessions: return jsonify({'status': 'error', 'message': 'Session expired'})
    
    s = sessions[session_id]
    data, err_data = s['data'], s['err_data']
    
    data['credentials_type'] = 'two_factor'
    data['twofactor_code'] = otp
    
    if 'uid' in err_data: data['userid'] = err_data['uid']
    if 'login_first_factor' in err_data: data['first_factor'] = err_data['login_first_factor']

    try:
        res = s['session'].post(f"{API_GRAPH}/auth/login", data=data, timeout=15).json()
        if 'access_token' in res:
            del sessions[session_id]
            return jsonify({'status': 'success', 'token': res['access_token']})
        return jsonify({'status': 'error', 'message': res['error'].get('message', 'Invalid OTP')})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 4. FORGET PASSWORD RECOVERY
@app.route('/api/recover_send', methods=['POST'])
def recover_send():
    uid = request.json.get('email')
    device = DeviceFingerprint()
    session = requests.Session()
    session.headers.update(device.get_headers())
    
    data = device.get_base_params()
    data.update({'uid': uid, 'credentials_type': 'password', 'fb_api_req_friendly_name': 'recover'})
    
    try:
        res = session.post(f"{API_GRAPH}/recover_accounts", data=data, timeout=15).json()
        if 'error' in res: return jsonify({'status': 'error', 'message': res['error'].get('message')})
        
        rec_id = str(uuid.uuid4())
        recover_sessions[rec_id] = {'uid': uid, 'device': device, 'session': session, 'data': data}
        return jsonify({'status': 'success', 'recover_id': rec_id, 'message': 'OTP Sent!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/recover_verify', methods=['POST'])
def recover_verify():
    rec_id = request.json.get('recover_id')
    otp = request.json.get('otp')
    if rec_id not in recover_sessions: return jsonify({'status': 'error', 'message': 'Session expired'})
    
    s = recover_sessions[rec_id]
    s['data'].update({'recovery_code': otp, 'fb_api_req_friendly_name': 'recover_verify_code'})
    
    try:
        res = s['session'].post(f"{API_GRAPH}/recover_accounts/verify", data=s['data'], timeout=15).json()
        if 'error' in res: return jsonify({'status': 'error', 'message': res['error'].get('message')})
        
        s['recovery_token'] = res.get('recovery_token') or res.get('token')
        return jsonify({'status': 'success', 'message': 'Code Verified'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/recover_reset_login', methods=['POST'])
def recover_reset_login():
    rec_id = request.json.get('recover_id')
    new_password = request.json.get('new_password')
    if rec_id not in recover_sessions: return jsonify({'status': 'error', 'message': 'Session expired'})
    
    s = recover_sessions[rec_id]
    
    try:
        pub_key, key_id = FacebookPasswordEncryptor.get_public_key()
        enc_pw = FacebookPasswordEncryptor.encrypt(new_password, pub_key, key_id)
        
        s['data'].update({'password': enc_pw, 'recovery_token': s['recovery_token'], 'fb_api_req_friendly_name': 'recover_change_password'})
        res = s['session'].post(f"{API_GRAPH}/recover_accounts/change_password", data=s['data'], timeout=15).json()
        
        if 'error' in res: return jsonify({'status': 'error', 'message': res['error'].get('message')})
            
        # Jugaad: Password change hote hi direct login
        token = internal_login(s['uid'], new_password, s['device'], s['session'])
        del recover_sessions[rec_id]
        
        if token:
            return jsonify({'status': 'success', 'token': token, 'message': 'Reset & Login Successful!'})
        return jsonify({'status': 'error', 'message': 'Password changed, but auto-login failed.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
