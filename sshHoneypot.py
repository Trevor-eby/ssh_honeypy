# Import library dependencies.
import datetime
import logging
from logging.handlers import RotatingFileHandler
import sys
import paramiko
import threading
import socket
import time
from pathlib import Path
from collections import Counter

# Constants.
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Get base directory of where user is running honeypy from.
base_dir = Path(__file__).parent.parent
# Source creds_audits.log & cmd_audits.log file path.
server_key = base_dir / 'ssh_honeypy' / 'static' / 'server.key'
creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'

# SSH Server Host Key.
host_key = paramiko.RSAKey(filename=server_key)

# Logging Format.
logging_format = logging.Formatter('%(asctime)s, %(message)s')

# Funnel (catch all) Logger.
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Credentials Logger. Captures IP Address, Username, Password.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")
    command = b""
    while True:  
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
            break

        command += char
        if char == b"\r":
            decoded_command = command.strip().decode(errors='ignore')
            funnel_logger.info(f'Command {decoded_command} executed by {client_ip}')

            if decoded_command == 'exit':
                response = b"\n Goodbye!\n"
                channel.send(response)
                channel.close()
                break
            elif command.strip() == b'pwd':
                response = b"\n" + b"\\usr\\local" + b"\r\n"
            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser1" + b"\r\n"
            elif command.strip() == b'ls':
                response = b"\n" + b"passwords.txt IMPORTANT.txt " + b"\r\n"
            elif command.strip() == b'cat passwords.txt':
                response = b"\n" + b"trevor 12345\n\rivan 678910" + b"\r\n"
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"
            
            channel.send(response)
            channel.send(b"corporate-jumpbox2$ ")
            command = b"\r"

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username and self.input_password:
            return paramiko.AUTH_SUCCESSFUL if username == self.input_username and password == self.input_password else paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"

        if tarpit:
            endless_banner = standard_banner * 100
            for char in endless_banner:
                channel.send(char)
                time.sleep(8)
        else:
            channel.send(standard_banner)
            emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()

def honeypot(address, port, username, password, tarpit=False):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    print(f"\n✅ SSH server is listening on {address}:{port}.")

    while True: 
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))
            ssh_honeypot_thread.start()
        except Exception as error:
            print("!!! Exception - Could not open new client connection !!!")
            print(error)

# === Analysis Features ===
def analyze_honeypot_logs(creds_log_path, cmd_log_path):
    from pathlib import Path
    import csv
    export_path = Path(cmd_log_path).parent / "honeypot_summary.csv"
    try:
        with open(creds_log_path, 'r') as f:
            creds_lines = []
            for line in f:
                parts = line.strip().split(', ')
                if len(parts) == 3:
                    creds_lines.append(parts)
        ips = [entry[0] for entry in creds_lines]
        usernames = [entry[1] for entry in creds_lines]
        passwords = [entry[2] for entry in creds_lines]

        with open(cmd_log_path, 'r') as f:
            cmd_lines = [line.strip() for line in f if "Command" in line]

        timestamps, commands, cmd_ips = [], [], []
        for line in cmd_lines:
            try:
                ts_part, cmd_part = line.split(", Command ")
                command, ip = cmd_part.split(" executed by ")
                timestamps.append(datetime.datetime.strptime(ts_part.strip(), "%Y-%m-%d %H:%M:%S"))
                commands.append(command.strip())
                cmd_ips.append(ip.strip())
            except ValueError:
                continue

        ip_counts = Counter(ips)
        username_counts = Counter(usernames)
        password_counts = Counter(passwords)
        command_counts = Counter(commands)
        hourly_distribution = Counter([t.hour for t in timestamps])

        print("=== SSH Honeypot Attack Summary ===")
        print("Top IPs:", ip_counts.most_common(3))
        #print("Top Commands:", command_counts.most_common(3))
        print("Frequent Usernames:", username_counts.most_common(3))
        print("Frequent Passwords:", password_counts.most_common(3))
        #print("Peak Attack Hours:", hourly_distribution.most_common(3))

    except FileNotFoundError:
        print("[!] Log files not found or incomplete. Try again after some activity.")

def start_honeypot_thread():
    t = threading.Thread(target=honeypot, args=('127.0.0.1', 2223, 'username', 'password'))
    t.daemon = True
    t.start()
    return t

def main():
    print("\n🚨 SSH Honeypot Interface 🚨")
    server_thread = start_honeypot_thread()
    print("✅ Honeypot server running on 127.0.0.1:2223")

    try:
        while True:
            print("\n--- Menu ---")
            print("1. View attack summary")
            print("2. Exit and shut down honeypot")
            choice = input("Choose an option: ")

            if choice == "1":
                analyze_honeypot_logs(creds_audits_log_local_file_path, cmd_audits_log_local_file_path)
            elif choice == "2":
                print("Shutting down honeypot server...")
                sys.exit(0)
            else:
                print("Invalid option. Please try again.")
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Shutting down.")
        sys.exit(0)

if __name__ == "__main__":
    main()
