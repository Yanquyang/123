import sm2
from gmssl.sm3 import sm3_kdf
from gmssl import sm4
import binascii
import socket
import threading
from typing import List

# socket绑定的ip
socket_ip = ('0.0.0.0', 38806)

# 存储所有发现的UAV实例
available_uavs: List[tuple] = []

# 用于监听广播的Socket
broadcast_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
broadcast_listener.bind(('', 37020))

def listen_for_broadcasts():
    while True:
        data, addr = broadcast_listener.recvfrom(1024)
        message = data.decode()
        if message.startswith("UAV@"):
            ip_port = message.split("@")[1]
            ip, port = ip_port.split(":")
            port = int(port)
            uav_info = (ip, port)
            if uav_info not in available_uavs:
                available_uavs.append(uav_info)
                print(f"Discovered UAV at {ip}:{port}")

# 启动广播监听线程
broadcast_listener_thread = threading.Thread(target=listen_for_broadcasts)
broadcast_listener_thread.daemon = True
broadcast_listener_thread.start()

# 等待发现UAV实例
while not available_uavs:
    pass

# 打印所有发现的UAV实例
print("Available UAVs:")
for i, uav in enumerate(available_uavs):
    print(f"{i+1}. {uav[0]}:{uav[1]}")

# 让用户选择一个UAV实例进行连接
selected_uav_index = int(input("Enter the number of the UAV to connect: "))
selected_uav = available_uavs[selected_uav_index - 1]
print(selected_uav)

def send_heartbeat(sock):
    """发送心跳包，并根据服务器回应决定是否继续发送心跳包"""
    try:
        sock.sendall("heartbeat".encode())  # 发送心跳包
        data = sock.recv(1024).decode()  # 接收回复
        if data == "alive":
            print("服务器存活，将在10秒后再次发送心跳包")
            threading.Timer(10, send_heartbeat, [sock]).start()
        else:
            print("服务器响应异常，停止发送心跳包")
    except socket.error as e:
        print(f"连接异常，停止发送心跳包: {e}")
        sock.close()


# GCS程序
def GCS():
    # 发送心跳包确认存活
    def client():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((selected_uav[0], selected_uav[1]))
        print("连接到无人机，发送心跳包检测无人机是否存活")
        s.sendall("heartbeat".encode())  # 发送心跳包
        data = s.recv(1024).decode()  # 接收回复
        if data == "alive":
            print("无人机存活，可以进行SM2密钥交换")
        return s

    s = client()

    # sm2密钥协商
    id_b = "42494C4C343536405941484F4F2E434F4D"
    entl_b = "0088"

    curve = sm2.Curve()

    user_b = sm2.Sm2KeyAgreement(curve, id_b, entl_b)

    p_b = user_b.curve.dot_to_bytes(user_b.pre_pub_key)
    r_b = user_b.curve.dot_to_bytes(user_b.tem_pub_key)
    z_b = user_b.id_auth_code

    # 获取用户B的公钥、身份认证码和消息的sm3哈希值
    user_a_data = sm2.send_user_b_data_get_user_a_data(p_b, r_b, z_b,
                                                       socket_ip)

    # 提取用户B的公钥、临时会话公钥和身份认证码
    p_a = user_a_data["p_a"]
    r_a = user_a_data["r_a"]
    z_a = user_a_data["z_a"]

    v_x, v_y = user_b.key_adgreement(p_a, r_a)

    k_a = sm3_kdf((v_x + v_y + z_a + z_b).encode(), user_b.klen)

    print("共享的密钥为：", k_a)

    # SM4加密函数
    def sm4_encrypt(key, data):
        if isinstance(key, str):
            # 如果key是字符串，首先将其转换为字节
            key = bytes.fromhex(key)
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key[:16], sm4.SM4_ENCRYPT)
        encrypted_data = crypt_sm4.crypt_ecb(data.encode())  # 使用ECB模式进行加密
        return encrypted_data

    # 使用socket发送加密数据
    def send_encrypted_message(ip, port, message, key):
        encrypted_message = sm4_encrypt(key, message)
        # 使用binascii.hexlify转换为十六进制字符串并打印
        print("加密后的消息(hex)：", binascii.hexlify(encrypted_message).decode())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(encrypted_message)
            print("加密消息已发送")

    # 定义用户B的服务器地址和端口
    server_address = (selected_uav[0], selected_uav[1])
    # 循环发送消息
    try:
        while True:
            message = input("请输入您想发送的消息（输入'exit'退出）：")
            if message == 'exit':
                break
            send_encrypted_message(server_address[0], server_address[1], message, k_a)
    finally:
        s.close()


GCS()