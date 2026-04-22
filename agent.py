import socket
import json
import sys

# Agent 的 Socket 路徑
SOCKET_PATH = "/var/run/clawos/ipc/agent.sock"

def test_connection():
    # 建立 Unix Domain Socket 
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print(f"正在連線至 {SOCKET_PATH}...")
        client.connect(SOCKET_PATH)
        
        # 準備一個測試指令 (根據你的 Agent 通訊協定調整)
        # 這裡假設發送一個 ping 或 status 指令
        message = {
            "command": "ping",
            "payload": "hello clawos"
        }
        
        print(f"發送指令: {message}")
        client.sendall(json.dumps(message).encode('utf-8'))
        
        # 接收回應
        response = client.recv(1024)
        print(f"收到回應: {response.decode('utf-8')}")
        
    except Exception as e:
        print(f"連線失敗: {e}")
        sys.exit(1)
    finally:
        client.close()

def add_routine():
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(SOCKET_PATH)
        
        # 建立一個 AI 任務指令
        message = {
            "command": "add_routine",
            "payload": {
                "name": "System_Check",
                "prompt": "檢查磁碟空間並回報",
                "interval": 60  # 每 60 秒執行一次
            }
        }
        
        client.sendall(json.dumps(message).encode('utf-8'))
        response = client.recv(1024)
        print(f"Agent 回應: {response.decode('utf-8')}")
        
    finally:
        client.close()

if __name__ == "__main__":
    test_connection()
    #add_routine()

