import socket
import threading
import pickle
import oqs
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Direct Messaging 기록 저장
direct_messages = {}
message_notifications = {}  # 알림을 저장할 변수 추가

def load_key(file_path):
    """키 파일을 로드"""
    with open(file_path, "rb") as file:
        return file.read()

def save_key(file_path, key):
    """키 파일을 저장"""
    with open(file_path, "wb") as file:
        file.write(key)

def request_public_key(target):
    """대상 노드의 공개키 요청"""
    central_ip = "172.17.0.7"  # 중앙 서버 IP
    request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        request_socket.connect((central_ip, 12345))  # 중앙 서버로 공개키 요청
        request_socket.sendall(pickle.dumps({"type": "key_request", "target": target}))
        public_key = request_socket.recv(4096)  # 공개키를 수신
        print(f"Public key received from {target}.")
        return public_key
    except Exception as e:
        print(f"Failed to get public key from {target}: {e}")
        return None
    finally:
        request_socket.close()

def encrypt_message(message, public_key_path):
    """메시지와 대칭키 암호화"""
    public_key = load_key(public_key_path)

    # Kyber를 사용해 대칭키 생성
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # AES-GCM으로 메시지 암호화
    iv = os.urandom(12)  # 12 bytes IV for AES-GCM
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

    return ciphertext, iv + encryptor.tag + encrypted_message

def decrypt_message(ciphertext, encrypted_message, private_key_path):
    """메시지와 대칭키 복호화"""
    kem = oqs.KeyEncapsulation('Kyber512')

    private_key = load_key(private_key_path)

    kem.generate_keypair()  # 키 쌍 생성
    kem.secret_key = private_key  # 비밀키 설정

    shared_secret = kem.decap_secret(ciphertext)

    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    actual_encrypted_message = encrypted_message[28:]
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv, tag), backend=default_backend())

    decryptor = cipher.decryptor()
    original_message = decryptor.update(actual_encrypted_message) + decryptor.finalize()

    return original_message
    

def send_direct_message(sender, target, message):
    """직접 메시지 전송 (중앙 서버를 거쳐)"""
    central_ip = "172.17.0.7"  # 중앙 서버 IP
    
    # 중앙 서버에 공개키 요청
    public_key = request_public_key(target)
    if public_key:
        save_key(f"{target}_public_key.bin", public_key)
    else:
        print(f"Failed to obtain public key for {target}. Message not sent.")
        return

    # 메시지 암호화
    public_key_path = f"{target}_public_key.bin"
    ciphertext, encrypted_message = encrypt_message(message, public_key_path)
    
    # 현재 시각
    current_time = datetime.now().strftime("%H:%M")

    # 데이터 패키지화
    data = {
        'type': 'message',  # 'type' 추가
        'ciphertext': ciphertext,
        'encrypted_message': encrypted_message,
        'sender': sender,
        'target': target,
        'time': current_time
    }
    
    if target not in direct_messages:
        direct_messages[target] = []
    direct_messages[target].append(f"You[{current_time}]: {message}")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((central_ip, 12345))  # 중앙 서버 포트 12345
    client_socket.send(pickle.dumps(data))
    print(f"message data size: {len(pickle.dumps(data))} bytes")
    client_socket.close()

    print(f"Direct message sent to {target} via Central Server.")

def receive_direct_messages(port, node_name, private_key_path):
    """직접 메시지 수신"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Node {node_name} listening for direct messages on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        data = pickle.loads(client_socket.recv(4096))

        if data['type'] == 'relay':
            print("Relay message received.")
            print(f"Relay data size: {len(pickle.dumps(data))} bytes")
            ciphertext = data['ciphertext']
            encrypted_message = data['encrypted_message']
            message_id = data['message_id']

            try:
                print("Relay start")
                partial_data = decrypt_message(ciphertext, encrypted_message, private_key_path)

                partial_data_dict = pickle.loads(partial_data)
                ciphertext = partial_data_dict['ciphertext']  # 암호화된 대칭키
                encrypted_message = partial_data_dict['encrypted_message']  # 암호화된 메시지

                print("Relay message decrpyted.")

                relay_data = {
                    'type': 'relay_response',
                    'sender': node_name,
                    'ciphertext': ciphertext,
                    'encrypted_message': encrypted_message,
                    'message_id': message_id
                }

                serialized_data = pickle.dumps(relay_data)
                print(f"Serialized relay data size: {len(serialized_data)} bytes")


                central_ip = "172.17.0.7"
                central_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                  central_socket.connect((central_ip, 12345))
                
                  central_socket.send(pickle.dumps(relay_data))
                  print("Relay response sent to Central Server.")
                except Exception as e:
                  print(f"Failed to send relay response: {e}")
                finally:
                  central_socket.close()

            except Exception as e:
                print("Failed to decrypt relay message.")

        elif data['type'] == 'message':
            
            print("Direct message received.")
            print(f"message data size: {len(data)} bytes")
            ciphertext = data['ciphertext']
            encrypted_message = data['encrypted_message']
            sender = data['sender']
            message_time = data.get('time', 'Unknown')  # 시간 정보를 가져옴
            print(f"Sender: {sender}")

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
            print("Unknown message.")
        
        client_socket.close()


def view_direct_messages(sender):
    """받은 직접 메시지 확인"""
    if sender not in direct_messages or not direct_messages[sender]:
        print(f"No messages from {sender}.")
        return

    print(f"--- Direct Messages from {sender} ---")
    for message in direct_messages[sender]:
        print(message)
    print("--- End of Direct Messages ---")

def serve_public_key(port, node_name, public_key_path):
    """공개키 요청에 응답"""
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

if __name__ == "__main__":
    # 현재 노드 이름 설정
    node_name = input("Enter the name of this node (A, B, C, D): ").strip().upper()
    private_key_path = f"{node_name}_private_key.bin"
    public_key_path = f"{node_name}_public_key.bin"

    # 공개키 요청 처리 스레드 시작
    threading.Thread(target=serve_public_key, args=(12345, node_name, public_key_path), daemon=True).start()

    # 메시지 수신 스레드 시작
    threading.Thread(target=receive_direct_messages, args=(12346, node_name, private_key_path), daemon=True).start()

    while True:
        print("Options:")
        print("[1] Send Direct Message")
        print("[2] View Direct Messages")
        print("[3] Exit")
        option = input("Select an option: ").strip()

        if option == "1":
            target = input("Enter the target user (A, B, C, D): ").strip().upper()
            message = input(f"Message to {target}: ").strip()
            send_direct_message(node_name, target, message)

        elif option == "2":
            sender = input("Enter the user to view messages from (A, B, C, D): ").strip().upper()
            view_direct_messages(sender)

        elif option == "3":
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.")
