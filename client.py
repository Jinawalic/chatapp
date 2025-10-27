import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
from custom_exceptions import NetworkError

# Shared encryption key (must match the server)
SECRET_KEY = b'FgF8nP5Z5uZkKmcBf2WcpE4G2hrK2Z2m_wIE5rI2BvA='
fernet = Fernet(SECRET_KEY)


class ChatClient:
    """Handles network connection for the client."""
    def __init__(self, host, port, username, app):
        self.host = host
        self.port = port
        self.username = username
        self.app = app
        self.sock = None
        self.running = True

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.sock.sendall(self.username.encode())
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            raise NetworkError(f"Failed to connect to server: {e}")

    def receive_messages(self):
        """Continuously receive messages from the server."""
        while self.running:
            try:
                msg = self.sock.recv(4096)
                if not msg:
                    break
                text = msg.decode().strip()

                if text.startswith("USERS::"):
                    users = text.replace("USERS::", "").split(",")
                    self.app.update_user_list(users)

                elif text.startswith("PRIVATE::"):
                    parts = text.split("::", 2)
                    if len(parts) == 3:
                        sender, encrypted_message = parts[1], parts[2]
                        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
                        self.app.display_private_message(sender, decrypted_message)

                else:
                    self.app.display_message(text)
            except Exception:
                break

        self.sock.close()
        self.app.display_message("Connection closed by server.")

    def send_message(self, message):
        try:
            self.sock.sendall(message.encode())
        except Exception:
            messagebox.showerror("Error", "Failed to send message.")
            self.running = False

    def send_private_message(self, receiver, message):
        """Send encrypted private message to another user."""
        encrypted = fernet.encrypt(message.encode()).decode()
        data = f"PRIVATE::{receiver}::{encrypted}"
        self.send_message(data)


class ChatApp:
    """Tkinter GUI for the chat client."""
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Group 16 Multi-User Chat Application")
        self.root.geometry("700x500")

        # === Main layout: Left (chat + input) | Separator | Right (users) ===
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # LEFT SIDE — Chat area + input below
        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Chat display area
        self.chat_area = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 0))

        # Bottom input area (message box + send button)
        bottom_frame = tk.Frame(left_frame)
        bottom_frame.pack(fill=tk.X, padx=5, pady=5)

        self.entry = tk.Entry(bottom_frame, font=("Arial", 10))
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(bottom_frame, text="Send", width=8, bg = "green", fg = "white", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)

        # Add a vertical separator line between chat and user list
        separator = tk.Frame(main_frame, width=2, bg="lightgrey")
        separator.pack(side=tk.LEFT, fill=tk.Y, padx=2)

        # RIGHT SIDE — Connected users list
        self.user_frame = tk.Frame(main_frame, width=180)
        self.user_frame.pack(side=tk.RIGHT, fill=tk.Y)
        tk.Label(self.user_frame, text="Connected Users", font=("Arial", 10, "bold")).pack(pady=(5, 0))
        self.user_list = tk.Listbox(self.user_frame)
        self.user_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_list.bind("<<ListboxSelect>>", self.open_private_chat)

        self.client = None
        self.private_chats = {}
        self.connect_window()

    def connect_window(self):
        """Ask for server IP, port, and username before connecting."""
        connect = tk.Toplevel(self.root)
        connect.title("Connect to Server")
        connect.geometry("300x200")

        tk.Label(connect, text="Server IP Address:").pack(pady=5)
        ip_entry = tk.Entry(connect)
        ip_entry.insert(0, "127.0.0.1")
        ip_entry.pack()

        tk.Label(connect, text="Port:").pack(pady=5)
        port_entry = tk.Entry(connect)
        port_entry.insert(0, "12345")
        port_entry.pack()

        tk.Label(connect, text="Username:").pack(pady=5)
        user_entry = tk.Entry(connect)
        user_entry.pack()

        def connect_server():
            host = ip_entry.get()
            port = int(port_entry.get())
            username = user_entry.get()
            if not username:
                messagebox.showwarning("Missing Info", "Please enter a username.")
                return
            try:
                self.client = ChatClient(host, port, username, self)
                self.client.connect()
                connect.destroy()
            except NetworkError as e:
                messagebox.showerror("Connection Error", str(e))

        tk.Button(connect, text="Connect", bg = "green", fg = "white", command=connect_server).pack(pady=10)

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if msg:
            self.client.send_message(msg)
            timestamp = self.get_timestamp()
            self.display_message(f"[{timestamp}] Me: {msg}")
            self.entry.delete(0, tk.END)

    def open_private_chat(self, event):
        """Open a separate private chat window with selected user."""
        selection = self.user_list.curselection()
        if not selection:
            return
        target = self.user_list.get(selection[0])
        if target == self.client.username or not target:
            return  # can't chat with self

        # If not already open, create new window
        if target not in self.private_chats:
            self.private_chats[target] = PrivateChatWindow(self, target)
        else:
            # Bring existing window to front
            self.private_chats[target].window.deiconify()
            self.private_chats[target].window.lift()

    def display_message(self, message):
        """Display messages in main chat area."""
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def display_private_message(self, sender, message):
        """Show received private messages in correct chat window."""
        if sender not in self.private_chats:
            self.private_chats[sender] = PrivateChatWindow(self, sender)
        self.private_chats[sender].display_message(f"{sender}: {message}")

    def update_user_list(self, users):
        self.user_list.delete(0, tk.END)
        for user in users:
            if user.strip():
                self.user_list.insert(tk.END, user.strip())

    def get_timestamp(self):
        import time
        return time.strftime("%H:%M:%S")

    def run(self):
        self.root.mainloop()


class PrivateChatWindow:
    """Dedicated chat window for private one-on-one messages."""
    def __init__(self, app, target):
        self.app = app
        self.target = target
        self.window = tk.Toplevel(app.root)
        self.window.title(f"You're Chatting Privately with {target}")
        self.window.geometry("420x400")

        # Frame for text area (chat history)
        chat_frame = tk.Frame(self.window)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 0))

        # Text display area
        self.text_area = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled', height=15)
        self.text_area.pack(fill=tk.BOTH, expand=True)

        # Frame for message entry and send button
        entry_frame = tk.Frame(self.window)
        entry_frame.pack(fill=tk.X, padx=5, pady=5)

        # Message input box
        self.entry = tk.Entry(entry_frame, font=("Arial", 10))
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_message)

        # Send button
        self.send_btn = tk.Button(entry_frame, text="Send", width=8, bg = "green", fg = "white", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)

        # Close handler
        self.window.protocol("WM_DELETE_WINDOW", self.close_window)

    def display_message(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state='disabled')
        self.text_area.yview(tk.END)

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if msg:
            self.app.client.send_private_message(self.target, msg)
            self.display_message(f"Me: {msg}")
            self.entry.delete(0, tk.END)

    def close_window(self):
        """When user closes this chat window."""
        self.app.private_chats.pop(self.target, None)
        self.window.destroy()


if __name__ == "__main__":
    ChatApp().run()
