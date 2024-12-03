import socket
import pickle
import os
import oqs
import random

SERVER_PORT = 12345
CLIENT_PORT = 12346

# 메시지 ID와 sender/target/time 매핑을 저장하는 전역 딕셔너리
message_map = {}

# 유저 관리하는 전역 딕셔너리
users = {
}

# 키 가져오기
def load_key(file_path):
    with open(file_path, "rb") as file:
        return file.read()

# 키 저장하기
def save_key(file_path, key):
    with open(file_path, "wb") as file:
        file.write(key)


# 공개키 요청 처리
def handle_key_request(data, client_socket):
    target = data['target']
    print(f"{target} Public key transmit.")
    if target in users:
        public_key = load_key(f"{target}_public_key.bin")
        client_socket.sendall(public_key)
    else:
        print(f"Public key for {target} not found.")
        client_socket.sendall(b"")

def handle_user_check(client_socket):
    try:
        user_names = list(users.keys())
        client_socket.sendall(pickle.dumps(user_names))
        print(f"User names sent: {user_names}")
    except Exception as e:
        print(f"Error sending user names: {e}")

# 중간 노드로 온 메시지 처리
def handle_relay_response(data):
    target = data['next']
    print(f"next : {target}")
    target_ip = users[target]['ip']
    
    try:
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_ip, 12346))
        target_socket.send(pickle.dumps(data))
        print(f"Message forwarded to {target} ({target_ip}).")
    except Exception as e:
        print(f"Error forwarding to final target: {e}")
    finally:
        target_socket.close()

# 사용자 등록 처리
def handle_user_registration(data, client_socket):
    node_name = data['node_name']
    ip_address = data['ip_address']
    public_key = data['public_key']

    if node_name in users:
        users[node_name]['ip'] = ip_address
        users[node_name]['publc_key'] = public_key
        client_socket.sendall(pickle.dumps({"status": "success", "message": f"User {node_name} updated successfully."}))
        print(f"User {node_name} updated with new IP {ip_address} and public key.")
    else:
        users[node_name] = {
            'name': node_name,
            'ip': ip_address,
            'publc_key': public_key
        }
        client_socket.sendall(pickle.dumps({"status": "success", "message": f"User {node_name} registered successfully."}))
        print(f"User {node_name} registered with IP {ip_address}.")

    save_key(f"{node_name}_public_key.bin", public_key)

if __name__ == "__main__":
    # 중앙 서버 실행
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', SERVER_PORT))
    server_socket.listen(5)
    print(f"Central Server listening on port {SERVER_PORT}...")

    while True:
        client_socket, addr = server_socket.accept()

        try:
            data = pickle.loads(client_socket.recv(4096))

            if 'type' not in data:
                print(f"Received data without 'type' key: {data}")
                continue

            if data['type'] == 'key_request':
                handle_key_request(data, client_socket)
            elif data['type'] == "check_user":
                handle_user_check(client_socket)
            elif data['type'] == 'node_registration':
                handle_user_registration(data, client_socket)
            elif data['type'] == 'message':
                handle_relay_response(data)
            else:
                print(f"Unknown type received: {data['type']}")
        except Exception as e:
            print(f"Error processing request: {e}")
        finally:
            client_socket.close()
