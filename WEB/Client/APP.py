import socket
import threading
import pickle
import oqs
import os
import random
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Flask 세션 비밀키 설정

# Direct Messaging 기록 저장
direct_messages = {}
message_notifications = {}  # 알림을 저장할 변수 추가

# 유저 관리하는 전역 딕셔너리
users = {
}

current_node = None

SERVER_IP = "192.168.0.19" # 서버 IP 주소
SERVER_PORT = 6000 # 소켓 외부 포트

USER_IP = "192.168.0.19" # 자신 IP 주소
USER_PORT = None

# Kyber 공개키 생성
def generate_kyber_keys(node_name):
    kem = oqs.KeyEncapsulation('Kyber512')
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()

    public_key_path = f"{node_name}_public_key.bin"
    private_key_path = f"{node_name}_private_key.bin"

    save_key(public_key_path, public_key)
    save_key(private_key_path, private_key)

    print(f"Kyber keys generated and saved for {node_name}.")

# 키 가져오기
def load_key(file_path):
    with open(file_path, "rb") as file:
        return file.read()

# 키 생성하기
def save_key(file_path, key):
    with open(file_path, "wb") as file:
        file.write(key)

# 수신자 공개키 요청
def request_public_key(target):
    request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        request_socket.connect((SERVER_IP, SERVER_PORT))  # 중앙 서버로 공개키 요청
        request_socket.sendall(pickle.dumps({"type": "key_request", "target": target}))
        public_key = request_socket.recv(4096)  # 공개키를 수신
        print(f"Public key received from server {target}.")
        save_key(f"{target}_public_key.bin", public_key)
    except Exception as e:
        print(f"Failed to get public key from server: {e}")
    finally:
        request_socket.close()

# 메시지 대칭키 암호화
def encrypt_message(message, sender, target, public_key):
    # Kyber를 사용해 대칭키 생성
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)

    data = {
        'message': message,
        'sender': sender,
        'target': target,
        'time': datetime.now().strftime("%H:%M")
    }

    # AES-GCM으로 메시지 암호화
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(pickle.dumps(data)) + encryptor.finalize()

    return ciphertext, iv + encryptor.tag + encrypted_message

# 중간 노드로 보낼 데이터 암호화
def encrypt_data_for_intermediate(data, public_key):
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    serialized_partial_data = pickle.dumps(data)
    encrypted_partial_data = encryptor.update(serialized_partial_data) + encryptor.finalize()

    return ciphertext, iv + encryptor.tag + encrypted_partial_data

# 메시지 복호화
def decrypt_message(ciphertext, encrypted_message, private_key_path):
    kem = oqs.KeyEncapsulation('Kyber512')

    private_key = load_key(private_key_path)

    kem.secret_key = private_key

    shared_secret = kem.decap_secret(ciphertext)

    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    actual_encrypted_message = encrypted_message[28:]
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv, tag), backend=default_backend())

    decryptor = cipher.decryptor()
    original_message = decryptor.update(actual_encrypted_message) + decryptor.finalize()

    return original_message
    
# 메시지 보내기
def send_message(sender, target, message):
    # 메시지 암호화
    public_key = load_key(f"{target}_public_key.bin")
    ciphertext, encrypted_message = encrypt_message(message, sender, target, public_key)

    # 데이터 패키지화
    data = {
        'type': 'message',
        'ciphertext': ciphertext,
        'encrypted_message': encrypted_message,
        'next': target
    }

    # 중간 노드 랜덤하게 선택
    intermediate_nodes = [node for node in users if node != sender and node != target]
    num = random.randint(1, len(intermediate_nodes))
    selected_nodes = random.sample(intermediate_nodes, num)
    print(f"Intermediate : {selected_nodes}")

    reversed_nodes = list(reversed(selected_nodes))
    for i, node in enumerate(reversed_nodes):
        public_key = load_key(f"{node}_public_key.bin")
        # 수정 중 일단 메시지 가장 처음 암호화는 함 이제 겹겹이 해야 됨
        ciphertext, encrypted_message = encrypt_data_for_intermediate(data, public_key)
        print(f"Encrypt for {node}")

        relay_data = {
            'type': 'message',
            'ciphertext': ciphertext,
            'encrypted_message': encrypted_message,
            'next': node
        }

        data = relay_data
    
    if target not in direct_messages:
        direct_messages[target] = []
    
    if target != sender:
      direct_messages[target].append(f"You[{datetime.now().strftime("%H:%M")}]: {message}")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    client_socket.send(pickle.dumps(data))

    client_socket.close()

    print(f"Direct message sent to {target} via Central Server.")


# 메시지 수신
def receive_messages(port, node_name, private_key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Node {node_name} listening for direct messages on port {port}.")

    while True:
        client_socket, addr = server_socket.accept()
        data = pickle.loads(client_socket.recv(4096))
        print(f"recevied message {data['type']}")
        
        if data['type'] == 'message':
            
            ciphertext = data['ciphertext']
            encrypted_message = data['encrypted_message']
            try:
                data = decrypt_message(ciphertext, encrypted_message, private_key)
                data_dict = pickle.loads(data)

                if 'sender' in data_dict:
                    print("Message received.")
                    sender = data_dict['sender']
                    message = data_dict['message']
                    message_time = data_dict['time']

                    if sender not in message_notifications:
                        message_notifications[sender] = 0
                    message_notifications[sender] += 1

                    if sender not in direct_messages:
                        direct_messages[sender] = []
                    direct_messages[sender].append(f"{sender}[{message_time}]: {message}")

                    print(f"New message from {sender}. Direct Messages to view.")
                else:
                    print("Relay message received.")
                    central_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                      central_socket.connect((SERVER_IP, SERVER_PORT))
                      central_socket.send(pickle.dumps(data_dict))
                      print("Relay response sent to Central Server.")
                    except Exception as e:
                        print(f"Failed to send relay response: {e}")
                    finally:
                        central_socket.close()
              
            except Exception as e:
              print(f"Failed to decrypt message: {e}")
            
        else:
            print("Unknown message.")
        
        client_socket.close()


# 중앙 서버에 등록
def register_node_with_server(node_name, public_key_path):
    try:
        if not os.path.exists(public_key_path):
            print(f"Public key file {public_key_path} not found.")
            return
        
        public_key = load_key(public_key_path)

        registration_data = {
            "type": "node_registration",
            "node_name": node_name,
            "ip": USER_IP,
            "port": USER_PORT,
            "public_key": public_key
        }

        print(f"USER PORT {USER_PORT}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_IP, SERVER_PORT))
            client_socket.sendall(pickle.dumps(registration_data))
            print(f"Node {node_name} registered with server at {SERVER_IP}:{SERVER_PORT}.")

    except Exception as e:
        print(f"Failed to register node with server: {e}")

# 서버 등록된 사용자 확인
def check_users(node_name):
    global users
    try:
        data = {
            "type": "check_user",
            "node_name": node_name,
            "ip": USER_IP,
            "port": USER_PORT,
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_IP, SERVER_PORT))
            client_socket.sendall(pickle.dumps(data))
            print(f"Node {node_name} registered with server at {SERVER_IP}:{SERVER_PORT}.")

            # 서버에서 사용자 목록 수신
            response = client_socket.recv(4096)  # 데이터 수신
            user_list = pickle.loads(response)
            print(f"Received user list: {user_list}")

            # 사용자 목록 최신화
            for user in user_list:
                if user not in users:
                    users[user] = None
            print(f"Updated users: {users}")

            # 사용자 공개키 요청
            for user in users:
                if user != node_name:
                    request_public_key(user)
    except Exception as e:
        print(f"Failed to check users: {e}")

# 로그인 보호 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):  # 세션에 로그인 상태가 없으면
            return redirect(url_for('home'))  # 로그인 페이지로 리디렉션
        return f(*args, **kwargs)
    return decorated_function



@app.route('/', methods=['GET', 'POST'])
def home():
    global current_node
    global USER_PORT

    if session.get('logged_in'):
        return redirect(url_for('chat_rooms'))
    
    if request.method == 'POST':
        data = request.json
        node_name = data.get('node_name', '').strip().upper()
        password = data.get('password', '').strip()
        print(f"login {node_name}, password {password}")
        data = {
            "type": "login",
            "node_name": node_name,
            "password": password
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((SERVER_IP, SERVER_PORT))
                client_socket.sendall(pickle.dumps(data))

                # 서버 응답 수신
                response = pickle.loads(client_socket.recv(4096))

                if response['status'] == 'success':
                    print("Success login")
                    private_key = f"{node_name}_private_key.bin"
                    current_node = node_name
                    session['logged_in'] = True  
                    session['node_name'] = node_name 

                    # 메시지 수신 스레드 시작
                    threading.Thread(target=receive_messages, args= (1236, node_name, private_key), daemon=True).start()
                    return jsonify({"status": "success", "message": "Registration successful"})
                else:
                    return jsonify({"status": "error", "message": response['message']}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to connect to the server: {str(e)}"}), 500

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.json  
        name = data.get('name', '').strip()
        node_name = data.get('node_name', '').strip().upper()
        password = data.get('password', '').strip()

        data = {
            "type": "register",
            "name": name,
            "node_name": node_name,
            "password": password
        }

        print(f"name : {name}. node_name {node_name}, {password}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((SERVER_IP, SERVER_PORT))
                client_socket.sendall(pickle.dumps(data))
                response = pickle.loads(client_socket.recv(4096))

                if response['status'] == 'success':
                    global USER_PORT
                    generate_kyber_keys(node_name)
                    public_key = f"{node_name}_public_key.bin"

                    if node_name == 'A':
                        USER_PORT = 6001
                    elif node_name == 'B':
                        USER_PORT = 6002
                    elif node_name == 'C':
                        USER_PORT = 6003
                    elif node_name == 'D':
                        USER_PORT = 6004

                    register_node_with_server(node_name, public_key)
                    return jsonify({"status": "success", "message": "Registration successful"})
                else:
                    return jsonify({"status": "error", "message": response['message']}), 400

        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to connect to the server: {str(e)}"}), 500

    return render_template('register.html')

@app.route('/chat_rooms', methods=['GET', 'POST'])
@login_required
def chat_rooms():
    global users
    if request.method == 'POST' and 'refresh' in request.form:
        check_users(current_node)

    return render_template('rooms.html', node_name=current_node, users=list(users.keys()))

@app.route('/chat_room', methods=['GET', 'POST'])
@login_required
def chat_room():
    global direct_messages
    target_user = request.args.get('target_user')
    if not target_user:
        return "<h1>No user selected!</h1>", 400

    raw_messages = direct_messages.get(target_user, [])
    messages = [
        {"sender": msg.split("[")[0],  
         "text": msg.split(": ")[1],  
         "time": msg.split("[")[1].split("]")[0]}  
        for msg in raw_messages
    ]

    print(f"Messages for {target_user}: {messages}")

    return render_template('room.html', target_user=target_user, messages=messages)

@app.route('/select_chat', methods=['POST'])
@login_required
def select_chat():
    target_user = request.form.get('target_user')
    if target_user:
        # /chat_room으로 리다이렉트
        return redirect(url_for('chat_room', target_user=target_user))
    return "<h1>No user selected!</h1>", 400

@app.route('/send_message', methods=['POST'])
@login_required
def send_message_route():
    data = request.get_json()
    target_user = data.get('target_user')
    message = data.get('message')

    if not target_user or not message:
        return {"status": "error", "message": "Invalid data"}, 400

    try:
        send_message(current_node, target_user, message)
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500
    
@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    target_user = request.args.get('target_user')
    if not target_user:
        return {"status": "error", "message": "No target user specified"}, 400

    user_messages = direct_messages.get(target_user, [])

    return {
        "status": "success",
        "messages": [
            {"sender": msg.split("[")[0],  # 메시지 송신자
             "text": msg.split(": ")[1],  # 메시지 내용
             "time": msg.split("[")[1].split("]")[0]}  # 메시지 시간
            for msg in user_messages
        ]
    }

@app.route('/logout', methods=['POST'])
def logout():
    global current_node, USER_PORT
    current_node = None  # 현재 사용자 초기화
    USER_PORT = None
    session.clear()  # 세션 데이터 삭제
    return redirect('/')  # 로그인 화면으로 리디렉션

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1235) 
