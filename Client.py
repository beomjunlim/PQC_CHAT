import socket
import threading
import pickle
import oqs
import os
import time
import random
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Direct Messaging 기록 저장
direct_messages = {}
message_notifications = {}  # 알림을 저장할 변수 추가

# 유저 관리하는 전역 딕셔너리
users = {
}

SERVER_IP = "172.17.0.3"
SERVER_PORT = 12345

USER_IP = None
USER_PORT = 12346

# 자신의 IP 주소
def get_current_ip():
    return socket.gethostbyname(socket.gethostname())

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
def encrypt_message(message, public_key):
    # Kyber를 사용해 대칭키 생성
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # AES-GCM으로 메시지 암호화
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

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
    # 중앙 서버에 공개키 요청
    for user in users:
        if user != sender:
            request_public_key(user)

    # 메시지 암호화
    public_key = load_key(f"{target}_public_key.bin")
    ciphertext, encrypted_message = encrypt_message(message, public_key)

    # 데이터 패키지화
    data = {
        'type': 'message',
        'ciphertext': ciphertext,
        'encrypted_message': encrypted_message,
        'sender': sender,
        'next': target,
        'target': target,
        'time': datetime.now().strftime("%H:%M")
    }

    # 중간 노드 랜덤하게 선택
    intermediate_nodes = [node for node in users if node != sender and node != target]
    num = random.randint(1, len(intermediate_nodes))
    selected_nodes = random.sample(intermediate_nodes, num)
    print(f"Intermediate : {selected_nodes}")

    reversed_nodes = list(reversed(selected_nodes))
    for i, node in enumerate(reversed_nodes):
        public_key = load_key(f"{node}_public_key.bin")
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
def receive_messages(port, node_name, private_key_path):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Node {node_name} listening for direct messages on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        data = pickle.loads(client_socket.recv(4096))

        if data['type'] == 'message':
            
            ciphertext = data['ciphertext']
            encrypted_message = data['encrypted_message']

            if 'target' in data:
                print("Direct message received.")
                ciphertext = data['ciphertext']
                encrypted_message = data['encrypted_message']
                sender = data['sender']
                message_time = data.get('time', 'Unknown')  

                try:
                  message = decrypt_message(ciphertext, encrypted_message, private_key_path)
                  message = message.decode('utf-8')

                  if sender not in message_notifications:
                      message_notifications[sender] = 0
                  message_notifications[sender] += 1

                  if sender not in direct_messages:
                      direct_messages[sender] = []
                  direct_messages[sender].append(f"{sender}[{message_time}]: {message}")

                  print(f"New message from {sender}. Check [2] View Direct Messages to view.")

                except Exception as e:
                  print("Failed to decrpyt message.")
            
            else:
                try:
                  print("Relay message received.")
                  partial_data = decrypt_message(ciphertext, encrypted_message, private_key_path)
                  partial_data_dict = pickle.loads(partial_data)
                  central_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  try:
                    central_socket.connect((SERVER_IP, SERVER_PORT))
                    central_socket.send(pickle.dumps(partial_data_dict))
                    print("Relay response sent to Central Server.")
                  except Exception as e:
                    print(f"Failed to send relay response: {e}")
                  finally:
                    central_socket.close()

                except Exception as e:
                  print(f"Failed to decrypt relay message: {e}")
            
        else:
            print("Unknown message.")
        
        client_socket.close()

# 메시지 확인하기
def view_direct_messages(sender):
    if sender not in direct_messages or not direct_messages[sender]:
        print(f"No messages from {sender}.")
        return

    print(f"--- Direct Messages from {sender} ---")
    for message in direct_messages[sender]:
        print(message)
    print("--- End of Direct Messages ---")

# 공개키 요청 응답
def serve_public_key(port, node_name, public_key_path):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Node {node_name} listening for public key requests on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        data = pickle.loads(client_socket.recv(4096))
        if data.get("type") == "key_request":
            print(f"Public key request received from {data['requester']}.")
            with open(public_key_path, "rb") as key_file:
                public_key = key_file.read()
            client_socket.sendall(public_key)
        client_socket.close()

# 중앙 서버에 등록
def register_node_with_server(node_name, public_key_path):
    try:
        global USER_IP
        USER_IP = get_current_ip()

        if not os.path.exists(public_key_path):
            print(f"Public key file {public_key_path} not found.")
            return
        
        public_key = load_key(public_key_path)

        registration_data = {
            "type": "node_registration",
            "node_name": node_name,
            "ip_address": USER_IP,
            "port": USER_PORT,
            "public_key": public_key
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_IP, SERVER_PORT))
            client_socket.sendall(pickle.dumps(registration_data))
            print(f"Node {node_name} registered with server at {SERVER_IP}:{SERVER_PORT}.")

    except Exception as e:
        print(f"Failed to register node with server: {e}")

def check_users(node_name):
    global users
    try:
        data = {
            "type": "check_user",
            "node_name": node_name,
            "ip_address": USER_IP,
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

            for user in user_list:
                if user not in users:
                    users[user] = None
            print(f"Updated users: {users}")
    except Exception as e:
        print(f"Failed to check users: {e}")

if __name__ == "__main__":
    node_name = input("Enter the name of this node (A, B, C, D): ").strip().upper()
    generate_kyber_keys(node_name)

    private_key_path = f"{node_name}_private_key.bin"
    public_key_path = f"{node_name}_public_key.bin"
    register_node_with_server(node_name, public_key_path)

    # 공개키 요청 처리 스레드 시작
    threading.Thread(target=serve_public_key, args=(SERVER_PORT, node_name, public_key_path), daemon=True).start()

    # 메시지 수신 스레드 시작
    threading.Thread(target=receive_messages, args= (USER_PORT, node_name, private_key_path), daemon=True).start()

    while True:
        
        print("Options:")
        print("[1] Send Direct Message")
        print("[2] View Direct Messages")
        print("[3] IP Check")
        print("[4] Exit")

        option = input("Select an option: ").strip()

        if option == "1":
            os.system('cls' if os.name == 'nt' else 'clear')
            check_users(node_name)
            target = input("Enter the target user (A, B, C, D): ").strip().upper()
            message = input(f"Message to {target}: ").strip()
            send_message(node_name, target, message)

        elif option == "2":
            os.system('cls' if os.name == 'nt' else 'clear')
            sender = input("Enter the user to view messages from (A, B, C, D): ").strip().upper()
            view_direct_messages(sender)

        elif option == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            currnet_ip = get_current_ip()
            if USER_IP != currnet_ip:
              register_node_with_server(node_name, public_key_path)
      
        elif option == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")
