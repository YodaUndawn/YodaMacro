from flask import Flask, request, jsonify
import json
import threading
import time
import hashlib
import os
import signal
import flask
import logging

app = Flask(__name__)


# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

valid_tokens_file = "valid_tokens.json"
used_tokens_file = "used_tokens.json"

valid_tokens = set()
used_tokens = set()



# Fungsi untuk hash password menggunakan SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_tokens():
    global valid_tokens, used_tokens
    try:
        with open(valid_tokens_file, "r") as file:
            valid_tokens_data = json.load(file)
            valid_tokens = set(valid_tokens_data["valid_tokens"])
    except FileNotFoundError:
        # Jika file tidak ditemukan, maka inisialisasi valid_tokens hanya dengan token `[D]YodaMacroVIP`
        valid_tokens = {"[D]YodaMacroVIP"}

    # Selalu tambahkan `[D]YodaMacroVIP` ke dalam valid_tokens, bahkan jika file ditemukan
    valid_tokens.add("[D]YodaMacroVIP")

    try:
        with open(used_tokens_file, "r") as file:
            used_tokens = set(json.load(file))
    except FileNotFoundError:
        used_tokens = set()


def save_tokens():
    # Jangan tambahkan `[D]YodaMacroVIP` ke dalam file valid_tokens.json
    with open(valid_tokens_file, "w") as file:
        json.dump({"valid_tokens": list(valid_tokens - {"[D]YodaMacroVIP"})}, file)

    with open(used_tokens_file, "w") as file:
        json.dump(list(used_tokens), file)

def save_user_data(username, password, token, device_id, uuid):
    username = username.lower()  # Convert username to lowercase
    hashed_password = hash_password(password)
    try:
        with open("user_data.json", "r") as file:
            user_data = json.load(file)
    except FileNotFoundError:
        user_data = {}

    if username in user_data:
        if user_data[username]["token"] is None:
            if user_data[username]["password"] == hashed_password:
                if token in valid_tokens:
                    valid_tokens.remove(token)
                    save_tokens()

                    # Jangan tambahkan token `[D]YodaMacroVIP` ke dalam used_tokens
                    if token != "[D]YodaMacroVIP":
                        used_tokens.add(token)
                        with open(used_tokens_file, "w") as file:
                            json.dump(list(used_tokens), file)

                    # Sisipkan UUID sebelum code_active
                    user_data[username]["token"] = token
                    user_data[username]["device_id"] = device_id
                    user_data[username]["uuid"] = uuid
                    user_data[username]["code_active"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    with open("user_data.json", "w") as file:
                        json.dump(user_data, file)
                    return True, "YDCode Has Been Updated"
                else:
                    return False, "Invalid YDCode. Please use a different Code."
            else:
                return False, "Incorrect password."
        return False, "Username is already in use. Please use another username."
    else:
        if token in valid_tokens and token not in used_tokens:
            # Tambahkan UUID sebelum code_active saat menambahkan pengguna baru
            user_data[username] = {"password": hashed_password, "token": token, "device_id": device_id, "uuid": uuid, "code_active": time.strftime('%Y-%m-%d %H:%M:%S')}
            with open("user_data.json", "w") as file:
                json.dump(user_data, file)

            # Jangan tambahkan token `[D]YodaMacroVIP` ke dalam used_tokens
            if token != "[D]YodaMacroVIP":
                used_tokens.add(token)
                with open(used_tokens_file, "w") as file:
                    json.dump(list(used_tokens), file)

            valid_tokens.remove(token)
            save_tokens()

            return True, "Registration successful."
        elif token not in valid_tokens:
            return False, "Invalid YDCode. Please request a new Code."
        elif token in used_tokens:
            return False, "Token has already been used before. Please request a new token."

def check_login(username, password):
    try:
        # Convert username to lowercase
        username = username.lower()

        with open("user_data.json", "r") as file:
            user_data = json.load(file)
            user_info = user_data.get(username, {})
            if user_info.get("token") is None:
                return False, "YDCode Expired Please Renew Code."
            elif user_info.get("password") == hash_password(password):
                return True, "Login successful!"
            else:
                return False, "Incorrect username or password."
    except FileNotFoundError:
        return False, "User data not found."



def periodic_token_check():
    while True:
        load_tokens()
        load_blocked_users
        time.sleep(10)  # Check every 10 seconds


def check_device_id(username, device_id):
    try:
        with open("user_data.json", "r") as file:
            user_data = json.load(file)
            user_info = user_data.get(username, {})
            if user_info:
                saved_device_id = user_info.get("device_id")
                if saved_device_id:
                    # Jika pengguna sudah pernah login sebelumnya
                    if saved_device_id == device_id:
                        return True  # Jika Device ID cocok, izinkan login
                    else:
                        return False  # Jika Device ID tidak cocok, tolak login
            return True  # Jika pengguna baru atau tidak ada Device ID yang tersimpan
    except FileNotFoundError:
        return True  # Jika file user_data.json tidak ditemukan, anggap pengguna baru


def get_ippublic():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

def get_client_ip():

    ipv4_address = request.form.get('ipv4_address')
    ipv6_address = request.form.get('ipv6_address')
    public_ip = get_ippublic()
    
    client_ip_info = {
        "ipv4_address": ipv4_address,
        "ipv6_address": ipv6_address,
        "public_ip": public_ip
    }
    
    return client_ip_info



def save_username_password(username, password,public_ip):
    username = username.lower()
    try:
        # Membuka file user_nohash.json untuk membaca data yang sudah ada
        with open("user_nohash.json", "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        # Jika file tidak ditemukan, maka data yang ada dianggap kosong
        existing_data = {}

    # Jika username belum ada dalam data yang ada, perbarui nilai-nilai jika null
    client_ip = get_client_ip()
    public_ip = public_ip if public_ip is not None else client_ip["public_ip"]

    # Tambahkan data baru ke dalam data yang sudah ada
    existing_data[username] = {
        "password": password,
        "ip_info": {
            "public_ip": public_ip
        }
    }

    # Simpan data yang telah diperbarui ke dalam file user_nohash.json
    with open("user_nohash.json", "w") as file:
        json.dump(existing_data, file, indent=4)

    # Periksa dan perbarui nilai-nilai jika null
    if username in existing_data:
        print(f"'{username}'.")
        return False  # Kembalikan False karena username sudah ada

    return True


def is_update_available():
    update_folder_path = 'Update'
    if os.path.exists(update_folder_path):
        if os.listdir(update_folder_path):
            return True  # Jika folder "Update" tidak kosong
    return False  # Jika folder "Update" kosong atau tidak ada

# Route untuk menampilkan halaman pembaruan
@app.route('/update')
def update_page():
    if is_update_available():
        return "Pembaruan tersedia! Silakan unduh dan pasang pembaruan baru."
    else:
        return "Tidak ada pembaruan yang tersedia saat ini."

@app.route('/login_success', methods=['POST'])
def login_success():
    username = request.form.get('username')
    password = request.form.get('password')

    public_ip = request.form.get('public_ip')
    
    if save_username_password(username, password, public_ip):
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Failed to save credentials."})


def load_blocked_users():
    with open('blocked_users.json', 'r') as file:
        data = json.load(file)
    return data["blocked_users"]

def load_user_messages():
    with open('userm.json', 'r') as file:
        data = json.load(file)
    return data.get("usersm", [])

@app.route('/check_connection', methods=['GET'])
def check_connection():
    username = request.args.get('user')
    
    # Ubah username menjadi lower case
    username = username.lower()
    
    blocked_users = load_blocked_users()
    user_messages = load_user_messages()
    
    for user in blocked_users:
        if 'username' in user and user['username'].lower() == username:
            return jsonify(status="Blocked User", reason=user["reason"])

    for user in user_messages:
        if 'username' in user and user['username'].lower() == username:
            ping_message = user.get("ping_message", "")
            return jsonify(status='Ping', ping_message=ping_message)

    return jsonify(status='Ping')


@app.route('/', methods=['POST'])
def index():
    client_ip = get_client_ip()
    print(f"Client's IPv4 Address: {client_ip['ipv4_address']}")  # Mencetak alamat IPv4 yang diterima
    print(f"Client's IPv6 Address: {client_ip['ipv6_address']}")  # Mencetak alamat IPv6 yang diterima
    return f"Client's IPv4 Address: {client_ip}"




@app.route('/login', methods=['POST'])
def login():
    client_ip = get_client_ip()
    username = request.form.get('username')
    password = request.form.get('password')
    uuid = request.form.get('uuid')
    device_id = request.form.get('device_id')

    version = request.args.get('version')
    if version != 'V1.8F' and version != 'V1.9':
        print(f"Update Needed:{username}")
        return jsonify(status='Error', message='Please update to V1.9. You can download V1.9 through the YodaCS Discord.')

    if username and password and device_id:
        try:
            with open("user_data.json", "r") as file:
                user_data = json.load(file)
                user_info = user_data.get(username)
                if user_info is None:
                    print(f"Username not found: {username}")
                    return jsonify({"status": "error", "message": "Username not found."})
                
                # Check password first
                elif user_info.get("password") == hash_password(password):  
                    if user_info.get("token") is None:
                        print(f"YDCode {username} Expired Please Renew.")
                        return jsonify({"status": "error", "message": "Your account has expired. Please resubscribe to regain access to our services"})
                    
                    saved_device_id = user_info.get("device_id")
                    
                    # Jika UUID tidak ada, simpan UUID yang diterima dari klien
                    if 'uuid' not in user_info or user_info['uuid'] is None:
                        user_info['uuid'] = uuid
                    
                    # If saved_device_id is not None and different from the received device_id
                    if saved_device_id and saved_device_id != device_id:
                        print(f"Login failed for user {username}: Different device used.")
                        return jsonify({"status": "error", "message": "Login failed. Please use the previously used device."})
                    
                    # If previous Device ID is null or matches the received device_id
                    if saved_device_id is None or saved_device_id == device_id:
                        # Store the new Device ID
                        user_info["device_id"] = device_id
                        with open("user_data.json", "w") as file:
                            json.dump(user_data, file)
                        
                        print(f"Login successful for user: {username}")
                        print(f"{client_ip}")
                        return jsonify({"status": "success", "message": "Login successful!"})
                else:
                    print(f"Incorrect username or password for user: {username},{client_ip}")
                    return jsonify({"status": "error", "message": "Incorrect username or password."})
        except FileNotFoundError:
            print("File user_data.json not found.")
            return jsonify({"status": "error", "message": "Server error."})
    else:
        print("Incomplete data.")
        return jsonify({"status": "error", "message": "Incomplete data."})

@app.route('/register', methods=['POST'])
def register():
    client_ip = get_client_ip()
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('token')
    uuid = request.form.get('uuid')
    device_id = request.form.get('device_id')  # Receive Device ID from client

    version = request.args.get('version')
    if version != 'V1.8F' and version != 'V1.9':
        print(f"Update Needed:{username}")
        return jsonify(status='Error', message='Please update to V1.9. You can download V1.9 through the YodaCS Discord.')

    # Check if username contains space
    if ' ' in username:
        return jsonify({"status": "error", "message": "Username cannot contain spaces. Please use _ instead."})

    # Check if data is complete
    if not all([username, password, token, device_id, uuid]):
        print("Incomplete data.")
        return jsonify({"status": "error", "message": "Incomplete data."})

    # Validate token first
    if token not in valid_tokens:
        print("Invalid token.")
        return jsonify({"status": "error", "message": "Invalid YDCode. Please use a different Code."})

    # Check if username already exists
    try:
        with open("user_data.json", "r") as file:
            user_data = json.load(file)
            if username.lower() in user_data:
                print(f"Username is already registered.: {username}")
                return jsonify({"status": "error", "message": f"Username '{username}' is already registered. Please use another username."})
    except FileNotFoundError:
        pass

    for user_name, user in user_data.items():
        if user.get("device_id") == device_id:
            user_name_capitalized = user_name.capitalize()
            print(f"Device ID is already registered: {user_name_capitalized}")
            return jsonify({
                "status": "error", 
                "message": f"PLEASE RESPECT THE DEVELOPER.\n\nYou have already created an account.\nYour previous username [ {user_name_capitalized} ]. \nPlease use the account you have created.\n\nPurchase a subscription to access this macro.\nIf you encounter any issues, contact Yoda via Discord."
            })

    # Periksa duplikat device_id dan uuid
    for user_name, user in user_data.items():
        if user.get("device_id") == device_id and user.get("uuid") == uuid:
            user_name_capitalized = user_name.capitalize()
            print(f"Device ID and UUID are already registered: {user_name_capitalized}")
            return jsonify({
                "status": "error", 
                "message": f"PLEASE RESPECT THE DEVELOPER.\n\nYou have already created an account.\nYour previous username [ {user_name_capitalized} ]. \nPlease use the account you have created.\n\nPurchase a subscription to access this macro.\nIf you encounter any issues, contact Yoda via Discord."
            })

    # Save the user data if all checks are passed
    success, message = save_user_data(username, password, token, device_id, uuid)
    if success:
        print(f"Registration successful: {username},{client_ip}")
        return jsonify({"status": "success", "message": message})
    else:
        print(f"Registration failed: {message}")
        return jsonify({"status": "error", "message": message})

@app.route('/verify_credentials', methods=['POST'])
def renew_code():
    client_ip = get_client_ip()
    username = request.form.get('username')
    password = request.form.get('password')
    new_token = request.form.get('new_token')
    device_id = request.form.get('device_id')  # Receive Device ID from client


    version = request.args.get('version')
    if version != 'V1.8F' and version != 'V1.9':
        print(f"Update Needed:{username}")
        return jsonify(status='Error', message='Please update to V1.9. You can download V1.9 through the YodaCS Discord.')

    # Check for missing data in the request
    if not all([username, password, new_token, device_id]):
        return jsonify({"status": "error", "message": "All fields are required.", "ip_address": client_ip})

    # Convert username to lowercase
    username = username.lower()

    try:
        with open("user_data.json", "r") as file:
            user_data = json.load(file)
            user_info = user_data.get(username)
            if user_info is None:
                return jsonify({"status": "error", "message": "Username not found.", "ip_address": client_ip})
            elif user_info.get("password") == hash_password(password):
                if user_info.get("device_id") == device_id:
                    if user_info.get("token") is None:
                        # Read valid_tokens.json
                        with open("valid_tokens.json", "r") as valid_tokens_file:
                            valid_tokens = json.load(valid_tokens_file)

                        # Check if the new token starts with "[D]"
                        if new_token.startswith("[D]"):
                            print(f"Renewal is not allowed : {username},{client_ip}")
                            return jsonify({"status": "error", "message": "Renewal using trial codes is not allowed. Please use a different YDCode.", "ip_address": client_ip})

                        # No longer hashing the new token
                        hashed_new_token = new_token

                        # Check if the new token matches any of the valid tokens
                        if hashed_new_token in valid_tokens["valid_tokens"]:
                            # Check if the new token has been used before
                            if hashed_new_token in used_tokens:
                                print(f"Token has been used before: {username},{client_ip}")
                                return jsonify({"status": "error", "message": "Token has been used before.", "ip_address": client_ip})
                            
                            # Update token in user_data.json
                            user_info["token"] = hashed_new_token
                            user_info["code_active"] = time.strftime('%Y-%m-%d %H:%M:%S')  # Update code active date
                            
                            # Save changes to file
                            with open("user_data.json", "w") as file:
                                json.dump(user_data, file)

                            # Mark the newly used token in used_tokens.json
                            used_tokens.add(hashed_new_token)
                            with open(used_tokens_file, "w") as file:
                                json.dump(list(used_tokens), file)
                            
                            # Remove the used token from valid_tokens.json
                            valid_tokens["valid_tokens"].remove(hashed_new_token)
                            with open("valid_tokens.json", "w") as file:
                                json.dump(valid_tokens, file)
                            print(f"YDCode has been renewed successfully: {username},{client_ip}")
                            return jsonify({"status": "success", "message": "YDCode has been renewed successfully.", "ip_address": client_ip})
                        else:
                            return jsonify({"status": "error", "message": "Invalid YDCode.", "ip_address": client_ip})
                    else:
                        return jsonify({"status": "error", "message": "YDCode Active. No need to renew YDCode.", "ip_address": client_ip})
                else:
                    return jsonify({"status": "error", "message": "Invalid device ID.", "ip_address": client_ip})
            else:
                return jsonify({"status": "error", "message": "Incorrect password.", "ip_address": client_ip})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Server error.", "ip_address": client_ip})



@app.route('/get_message', methods=['GET'])
def get_message():

    try:
        # Baca pesan dari file pesan.json
        with open("pesan.json", "r") as file:
            data = json.load(file)
            message = data.get("message")
            if message:
                print(f"GET INFO")
                return jsonify({"status": "success", "message": message})
            else:
                return jsonify({"status": "error", "message": "No message found."})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File 'pesan.json' not found."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})



@app.route('/shutdown', methods=['POST'])
def shutdown_server():
    if request.method == 'POST':
        # Hanya izinkan shutdown jika permintaan datang dari localhost
        if request.remote_addr == '127.0.0.1':
            time.sleep(1)  # Tunggu 1 detik sebelum menghentikan server
            os.kill(os.getpid(), signal.SIGINT)
            return 'Server shutting down...'


def shutdown():
    time.sleep(1)
    func = flask.request.environ.get('werkzeug.server.shutdown')
    if func:
        func()


if __name__ == '__main__':
    load_tokens()
    app.logger.info("Starting server...")
    threading.Thread(target=periodic_token_check, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=80)