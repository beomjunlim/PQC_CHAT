import socket
import pickle
import os
import oqs
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 메시지 ID와 sender/target/time 매핑을 저장하는 전역 딕셔너리
message_map = {}

def load_key(file_path):
    """키 파일을 로드"""
    with open(file_path, "rb") as file:
        return file.read()


def save_key(file_path, key):
    """키 파일을 저장"""
    with open(file_path, "wb") as file:
        file.write(key)


users = {
    'A': {'name': 'A', 'ip': '172.17.0.2', 'public_key': load_key("A_public_key.bin")},
    'B': {'name': 'B', 'ip': '172.17.0.4', 'public_key': load_key("B_public_key.bin")},
    'C': {'name': 'C', 'ip': '172.17.0.5', 'public_key': load_key("C_public_key.bin")},
    'D': {'name': 'D', 'ip': '172.17.0.6', 'public_key': load_key("D_public_key.bin")}
}


def encrypt_data_for_intermediate(data, public_key):
    """중간 노드로 보낼 데이터를 암호화"""
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    partial_data = {
        'encrypted_message': data['encrypted_message'],
        'ciphertext': data['ciphertext']
    }

    serialized_partial_data = pickle.dumps(partial_data)
    encrypted_partial_data = encryptor.update(serialized_partial_data) + encryptor.finalize()

    return ciphertext, iv + encryptor.tag + encrypted_partial_data


def handle_key_request(data, client_socket):
    """공개키 요청 처리"""
    target = data['target']
    print(f"{target} Public key transmit.")
    if target in users:
        client_socket.sendall(users[target]['public_key'])
    else:
        print(f"Public key for {target} not found.")
        client_socket.sendall(b"")  # 공개키를 찾지 못한 경우 빈 바이트를 반환


def handle_message(data):
    """message 타입 처리 - 메시지를 중간 노드로 전달"""
    sender = data['sender']
    target = data['target']
    time = data['time']

    # 메시지 ID 생성 및 sender/target 저장
    message_id = f"{sender}-{target}-{random.randint(1000, 9999)}"
    message_map[message_id] = {'sender': sender, 'target': target, 'time': time}

    intermediate_nodes = [node for node in users if node != sender and node != target]
    print(f"Message data size: {len(pickle.dumps(data))} bytes")

    if intermediate_nodes:
        intermediate_node = random.choice(intermediate_nodes)
        intermediate_ip = users[intermediate_node]['ip']
        ciphertext, encrypted_message = encrypt_data_for_intermediate(data, users[intermediate_node]['public_key'])

        relay_data = {
            'type': 'relay',
            'ciphertext': ciphertext,
            'encrypted_message': encrypted_message,
            'sender': 'centralServer',
            'target': intermediate_node,
            'message_id': message_id  # 메시지 ID 포함
        }

        send_to_intermediate_node(intermediate_ip, relay_data)


def send_to_intermediate_node(intermediate_ip, relay_data):
    """중간 노드로 데이터를 전송"""
    try:
        intermediate_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        intermediate_socket.connect((intermediate_ip, 12346))
        intermediate_socket.send(pickle.dumps(relay_data))
        print(f"Relay message sent to intermediate node ({intermediate_ip}).")
        print(f"Relay data size: {len(pickle.dumps(relay_data))} bytes")
    except Exception as e:
        print(f"Error sending to intermediate node: {e}")
    finally:
        intermediate_socket.close()


def handle_relay_response(data):
    """relay_response 타입 처리 - 중간 노드 응답을 최종 대상에게 전달"""
    ciphertext = data['ciphertext']
    encrypted_message = data['encrypted_message']
    message_id = data['message_id']
    print(f"Target data size: {len(pickle.dumps(data))} bytes")

    # 메시지 ID를 통해 sender/target 조회
    if message_id not in message_map:
        print(f"Unknown message ID: {message_id}")
        return

    sender = message_map[message_id]['sender']
    target = message_map[message_id]['target']
    time = message_map[message_id]['time']

    if target in users:
        target_ip = users[target]['ip']
        try:
            target_data = {
                'type': 'message',
                'ciphertext': ciphertext,
                'encrypted_message': encrypted_message,
                'sender': sender,
                'target': target,
                'time': time
            }
            print(f"Target data send: {len(pickle.dumps(target_data))} bytes")

            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((target_ip, 12346))
            target_socket.send(pickle.dumps(target_data))

            print(f"Message forwarded to final target {target} ({target_ip}).")
        except Exception as e:
            print(f"Error forwarding to final target: {e}")
        finally:
            target_socket.close()
    else:
        print(f"Target {target} not found.")


def central_server(port):
    """중앙 서버 - 타입별로 요청 처리"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Central Server listening on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()

        try:
            data = pickle.loads(client_socket.recv(4096))

            if 'type' not in data:
                print(f"Received data without 'type' key: {data}")
                continue

            if data['type'] == 'key_request':
                handle_key_request(data, client_socket)
            elif data['type'] == 'message':
                handle_message(data)
            elif data['type'] == 'relay_response':
                handle_relay_response(data)
            else:
                print(f"Unknown type received: {data['type']}")
        except Exception as e:
            print(f"Error processing request: {e}")
        finally:
            client_socket.close()


def central_server_start():
    """중앙 서버를 시작하는 함수"""
    port = 12345
    central_server(port)


if __name__ == "__main__":
    # 중앙 서버 실행
    central_server_start()
