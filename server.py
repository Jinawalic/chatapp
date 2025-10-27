import socket
import threading
import time
from custom_exceptions import NetworkError
from cryptography.fernet import Fernet

# Shared encryption key (same for all)
SECRET_KEY = b'FgF8nP5Z5uZkKmcBf2WcpE4G2hrK2Z2m_wIE5rI2BvA='
fernet = Fernet(SECRET_KEY)


class ClientHandler(threading.Thread):
    """Handles each client connection."""
    def __init__(self, conn, addr, server):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.server = server
        self.username = None
        self.running = True

    def run(self):
        try:
            # Step 1: Get username
            self.username = self.conn.recv(1024).decode().strip()
            if not self.username:
                raise NetworkError("Username not provided.")

            print(f"[SERVER] {self.username} joined from {self.addr}")
            self.server.register_client(self)
            time.sleep(0.2)
            self.server.broadcast(f"SERVER: {self.username} has joined the chat!")

            # Step 2: Handle incoming messages
            while self.running:
                msg = self.conn.recv(4096)
                if not msg:
                    break
                text = msg.decode().strip()

                # Private message handling
                if text.startswith("PRIVATE::"):
                    parts = text.split("::", 2)
                    if len(parts) == 3:
                        _, receiver, encrypted_message = parts
                        self.server.send_private_message(self.username, receiver, encrypted_message)
                else:
                    timestamp = time.strftime("%H:%M:%S")
                    full_msg = f"[{timestamp}] {self.username}: {text}"
                    print(full_msg)
                    self.server.broadcast(full_msg, exclude=self)

        except Exception as e:
            print(f"[SERVER] Error with {self.addr}: {e}")

        finally:
            self.server.remove_client(self)
            self.conn.close()
            print(f"[SERVER] {self.username} disconnected.")
            self.server.broadcast(f"SERVER: {self.username} has left the chat!")

    def send(self, message):
        """Send message to this client."""
        try:
            self.conn.sendall((message + "\n").encode())
        except Exception as e:
            print(f"[SERVER] Failed to send to {self.username}: {e}")
            self.running = False


class ChatServer:
    """Main chat server that manages all clients."""
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.clients = []
        self.clients_lock = threading.Lock()

    def start(self):
        print(f"[SERVER] Starting server on {self.host}:{self.port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        print("[SERVER] Waiting for clients to connect...")

        while True:
            conn, addr = s.accept()
            handler = ClientHandler(conn, addr, self)
            handler.start()

    def register_client(self, handler):
        with self.clients_lock:
            self.clients.append(handler)
        self.send_user_list_update()

    def remove_client(self, handler):
        with self.clients_lock:
            if handler in self.clients:
                self.clients.remove(handler)
        self.send_user_list_update()

    def broadcast(self, text, exclude=None):
        """Send message to all connected clients."""
        with self.clients_lock:
            clients_copy = list(self.clients)
        for c in clients_copy:
            if c is exclude:
                continue
            try:
                c.send(text)
            except Exception:
                self.remove_client(c)

        self.send_user_list_update()

    def send_private_message(self, sender, receiver, encrypted_message):
        """Forward encrypted private message to the intended recipient."""
        with self.clients_lock:
            for client in self.clients:
                if client.username == receiver:
                    client.send(f"PRIVATE::{sender}::{encrypted_message}")
                    print(f"[SERVER] Private message from {sender} to {receiver}")
                    return
        print(f"[SERVER] User {receiver} not found for private message.")

    def send_user_list_update(self):
        """Send all usernames to everyone."""
        with self.clients_lock:
            users = [c.username for c in self.clients if c.username]
        update = "USERS::" + ",".join(users)
        for c in list(self.clients):
            try:
                c.send(update)
            except Exception:
                self.remove_client(c)


if __name__ == "__main__":
    try:
        server = ChatServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Server stopped.")
