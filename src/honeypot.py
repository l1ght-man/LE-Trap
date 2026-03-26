import socket
import datetime
import json
import time
import threading
from pathlib import Path
import docker
import select
import os
import urllib.parse
import paramiko
import logging

# Suppress paramiko SSH protocol errors (expected from attack simulator)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# Configuration
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

class Honeypot:
    def __init__(self, ports=[22,21,80,23]):
                # === AUTHENTICATION CREDENTIALS ===
        # Change these as you wish
        self.VALID_USERS= {
            'admin': 'admin',
            'root': 'password',
            'user': 'userpass'
        }
        self.host_key = paramiko.RSAKey.generate(2048)    
        self.ports = ports
        self.connections = {port: 0 for port in ports}
        self.conn_lock = threading.Lock()
        threading.Thread(target=self.show_status, daemon=True).start()
        with open ('web/fake_website.html' , 'rb') as f:
            html_content = f.read()
        html_content = html_content.strip()
        content_length = len(html_content)
        self.banners = {
    22: b"SSH-2.0-FakeSSH\r\n",
    21: b"",
    80: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: " + str(content_length).encode() + b"\r\n" 
        b"Connection: close\r\n"
        b"\r\n" 
        + html_content
        ),
    23: b""
}
    def show_status(self):
         while True:
              time.sleep(1)
              with self.conn_lock:
                   status = " | ".join(f"Port{p}:{self.connections[p]}" for p in sorted(self.connections) if p != 80)
                   if status:
                        print(f"\r [+] {status:<40}     ", end='' , flush=True )

    def handle_telnet_login(self , client_sock , ip):
        """Step 1 : Login Screen + Brute force login """
        client_sock.settimeout(None)
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client_sock.send(bytes([255, 251, 1]))  # WILL ECHO
        client_sock.send(bytes([255, 251, 3]))  # WILL SGA  
        client_sock.send(bytes([255, 252, 34])) # WONT LINEMODE
        client_sock.send(b"\r\n" * 3)
        client_sock.send(b"Ubuntu 22.04.4 LTS Production Server\r\n")
        client_sock.send(b"===================================================\r\n\r\n")
        username = self.prompt_user(client_sock, ip , b'Login: ')
        if not username:
            client_sock.close()
            return
        password = self.prompt_user(client_sock , ip ,b'Password: ' , hide= True)
        if not password:
            client_sock.close()
            return
        # Filter out any non-printable characters
        username = ''.join(c for c in username if c.isprintable()).strip()
        password = ''.join(c for c in password if c.isprintable()).strip()
        self.log_activity(ip , 23 , f"LOGIN ATTEMPT: {username} {password}")
        
        if username in self.VALID_USERS and self.VALID_USERS[username] == password:
             client_sock.send(b"Welcome back, " + username.encode() +b"!\r\n\r\n")
             self.start_docker_honeypot(client_sock, ip)
        else:
             client_sock.send(b"\r\nLogin incorrect.\r\n")
             self.log_activity(ip , 23,f"LOGIN FAILED: {username}")
             client_sock.close()
    def handle_ssh_client(self , client_sock , ip):
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(self.host_key)
        server_interface = SSHHoneypotInterface(self.VALID_USERS)
        transport.start_server(server=server_interface)
        channel = transport.accept(timeout=30)

        if channel is None:
            transport.close()
            return
        else:
             self.log_activity(ip , 22 ,"SSH_LOGIN", "Successful authentication")
             self.start_docker_honeypot_ssh(channel,ip)
    def start_docker_honeypot_ssh(self, channel, ip):
                # --- ESCAPE TRAP TOGGLES (Enable these to make it IMPOSSIBLE to exit) ---
        TRAP_ESCAPES = False # Set to False if you want real exit behavior
        try:
            client = docker.from_env()
            print(f" \n[*] Spawning container for {ip}...", flush=True)
        except Exception as e:
            print(f"\n[!] Docker error for {ip}: {e}", flush=True)
            channel.send(b"\r\nSystem error. Connection closed.\r\n")
            channel.close()
            return
        
        trap_path = Path.cwd()
        startup_cmd = "bash -c 'stty -echo; exec bash --noediting'"
        # container running
        try:
            container = client.containers.run(
                "honeypot/ubuntu-locked:latest", 
                startup_cmd,
                detach=True, 
                tty=True, 
                stdin_open=True,
                hostname="prod-db-01",
                mem_limit="128m",
                cpu_quota=50000,
                network_mode="none",
                pids_limit=50,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                read_only=True,
                tmpfs={"/tmp": "size=10m,mode=1777"},
                auto_remove=True
            )
        except Exception as e:
            print(f"\n [!] Container creation failed for {ip}: {e}", flush=True)
            channel.send(b"\r\nSystem initialization failed.\r\n")
            channel.close()
            return
        
        print(f"\n[*] Container started for {ip}", flush=True)
        try:
            # Use exec_run instead of attach_socket for proper socket support
            # Disable echo with stty to prevent double-echoing
            exec_result = container.exec_run(
                "/bin/bash -c 'stty -echo; exec bash --noediting'",
                stdin=True,
                stdout=True,
                stderr=True,
                tty=True,
                socket=True
            )
            docker_sock = exec_result.output._sock  # Get the actual socket
            
            channel.send(b"Connected to Ubuntu 22.04.4 LTS\r\n")
            
              
            t = threading.Thread(target=self.docker_output_reader, args=(docker_sock, channel))
            t.daemon = True
            t.start() 
            command_buffer = b""
            escape_mode = False
            escape_buff = b""
            max_escape_buff = 8 
            while True:
                        hacker_input = channel.recv(1024)
                        if not hacker_input : break
                        clean_input = b""
                        for byte in hacker_input :
                            b = bytes([byte])
                            if TRAP_ESCAPES and byte == 3 :
                                 channel.send(b"\r\n^c\r\nroot@production-server:/#")
                                 command_buffer = b""
                                 continue
                            if TRAP_ESCAPES and byte == 26 :
                                 channel.send(b"\r\n[1]+  Stopped                 bash\r\nroot@production-server:/# ")
                                 command_buffer = b""
                                 continue
                            if TRAP_ESCAPES and byte == 4 :
                                channel.send(b"\r\nlogout\r\nConnection closed by foreign host.\r\n")
                                time.sleep(1)  # Dramatic pause
                                channel.send(b"Connected to Ubuntu 22.04.4 LTS\r\nroot@production-server:/# ")
                                command_buffer = b""
                                continue

                            
                            if escape_mode :
                                escape_buff += b
                                if b in b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ~" or len(escape_buff) > max_escape_buff:
                                      escape_mode = False
                                      escape_buff = b""
                                continue
                            if b == b"\x1b" :
                                 escape_mode = True
                                 escape_buff = b""
                                 continue      



                            if byte == 127 or byte == 8 :
                                if len(command_buffer) > 0:
                                    channel.send(b'\b \b')
                                    docker_sock.send(b'\x7f')
                                    command_buffer = command_buffer[:-1]
                                continue
                            if byte < 128:
                                    char = bytes([byte])
                                    if char == b'\n' or char == b'\r'  :
                                        channel.send(b'\r\n')
                                        docker_sock.send(b'\n')
                                        try:
                                             decoded_cmd = command_buffer.decode('utf-8', errors='ignore').strip()
                                             if decoded_cmd: 
                                                  self.log_activity(ip, 22, f"CMD: {decoded_cmd}")
                                        except:pass
                                        command_buffer = b""
                                    else:
                                        channel.send(char)
                                        docker_sock.send(char)
                                        command_buffer += char 

                        if clean_input:
                            if TRAP_ESCAPES and (b'\r' in clean_input or b'\n' in clean_input):
                                 cmd = command_buffer.decode('utf-8', errors='ignore').strip().lower()
                                 if cmd in ['exit','logout','bye','quit']:
                                      channel.send(b"\r\nlogout\r\nConnection closed by foreign host.\r\n")
                                      time.sleep(1)
                                      channel.send(b"Connected to Ubuntu 22.04.4 LTS\r\nroot@production-server:/#")
                                      command_buffer = b""
                                      continue



                            if b'\r' in clean_input or b'\n' in clean_input :
                                    channel.send(b'\r\n')
                                    docker_sock.send(b'\n')   
                            else:
                                    channel.send(clean_input)
                                    docker_sock.send(clean_input)   
                                        
                                    command_buffer += clean_input
                                    try:
                                       decoded_cmd = command_buffer.decode('utf-8',errors='ignore').strip()
                                       if decoded_cmd:
                                             self.log_activity(ip , 23 , f"CMD: {decoded_cmd}" )
                                    except : pass
                                    command_buffer = b""
        except Exception as e:
            print(f"\n[!] Docker session error for {ip}: {e}", flush=True)
            self.log_activity(ip, 23, f"DOCKER_ERROR: {str(e)}")
        finally:
            print(f"\n[*] Killing container for {ip}", flush=True)
            try:
                container.stop()
            except:
                pass
            try:
                channel.close()
            except:
                pass
              

    def handle_ftp_session(self, sock, ip):
        """simulate ftp server with command logging"""
        sock.send(b"220 FTP Server (vsftpd 3.0.3) ready.\r\n")
        sock.send(b"220 *** UNAUTHORIZED ACCESS PROHIBITED ***\r\n")

        try:
             buffer = ""
             while True:
                    data = sock.recv(1024).decode('utf-8', errors='ignore')
                    if not data:
                        break
                    buffer += data
                    while '\n' in buffer:
                        line , buffer = buffer.split('\n',1)
                        line = line.strip()
                        if not line:
                             continue
                            
                        parts = line.split(maxsplit=1)
                        cmd = parts[0].upper() if parts else ""
                        arg = parts[1] if len(parts) > 1 else ""

                        self.log_activity(ip, 21, "FTP-COMMAND", f"{cmd} {arg}")
                        
                        if cmd == "USER" :
                            sock.send(b"331 Please specify password.\r\n")
                           
                        elif cmd == "PASS":
                            pwd_preview = arg[:50] if arg else "[EMPTY]"
                            self.log_activity(ip, 21, "FTP_LOGIN", f"password={pwd_preview}")
                            sock.send(b"230 Login successful.\r\n")
                            self.log_activity(ip, 21, "FTP_LOGIN", f"user={arg}")
                            print(f"\n[FTP] {datetime.datetime.now().strftime('%H:%M:%S')} | {ip}")
                            print(f"   IP: {ip} | Password: '{pwd_preview}'\n", flush=True) 
                        elif cmd == "LIST":
                            sock.send(b"150 Opening ASCII mode data connection.\r\n")
                            sock.send(b"drwxr-xr-x 2 root root 4096 Jan 15 10:23 backups\r\n")
                            sock.send(b"-rw-r--r-- 1 root root  284 Jan 15 10:20 .env\r\n")
                            sock.send(b"-rw------- 1 root root 1679 Jan 14 08:11 id_rsa\r\n")
                            sock.send(b"226 Directory send OK.\r\n")
                        elif cmd in ["QUIT", "EXIT"]:
                            sock.send(b"221 Goodbye.\r\n")
                            break
                        else:
                            sock.send(b"500 Unknown command.\r\n")
        except Exception as e:
                self.log_activity(ip, 21, "FTP_ERROR", str(e))
        finally:
                sock.close()

    def prompt_user(self , client_sock , ip , prompt_text , hide=False):
         """Get username/password with visual feedback"""
         client_sock.send(b"\r\n" + prompt_text)
         response = b""
         try:
            while True :
                        data = client_sock.recv(1)
                        if not data :
                            return None
                        char = data[0]
                        if char == 13 or char == 10 :
                            client_sock.send(b"\r\n")
                            return response.decode('utf-8', errors='ignore')            
                        if hide and 32 <= char <= 126 :
                            client_sock.send(b"*")
                        elif 32 <= char <= 126 :
                            client_sock.send(bytes([char]))
                        response += bytes([char])
        
         except socket.TimeoutError :    
            client_sock.send(b"\r\nTimeout.\r\n")
            return None
    
    def log_activity(self, ip , port ,event_type, details=""):
        timestamp = datetime.datetime.now().isoformat()
        credentials = None
        if 'username=' in details and 'password=' in details :
            try:
                if '?' in details:
                      query = details.split('?')[1].split(' ')[0]
                      params = urllib.parse.parse_qs(query)
                else:
                     params= urllib.parse.parse_qs(details)
                user = params.get('username', params.get('user', ['']))[0]
                pwd = params.get('password', params.get('pass', ['']))[0]
                if user or pwd:
                     credentials = {"username": user[:50], "password": pwd[:50]}
                     event_type = "CREDENTIAL_SUBMISSION"
            except:
                 pass
            
        activity = {
            "timestamp": timestamp,
            "source_ip": ip,
            "port": port,
            "service": {21: "ftp", 22: "ssh", 23: "telnet", 80: "http"}.get(port, "unknown"),
            "event_type" : event_type,
            "details": details[:500],
        }
        if credentials:
            activity["credentials"] = credentials
            print(f"\n[CRED] {timestamp.split('T')[1][:8]} | {ip} | {activity['service'].upper()}")
            print(f"       User: {credentials['username']} | Pass: {credentials['password']}\n", flush=True)
        log_file = LOG_DIR / f"honeypot_{datetime.date.today()}.jsonl"
        with open(log_file, "a", encoding='utf-8') as f :
            f.write(json.dumps(activity, ensure_ascii=False)+ "\n")
    def alert_high_risk(self, ip, port, event_type, details=""):
        """Simple console alert for high-risk events"""
        alert_msg = f"\n[ALERT] {datetime.datetime.now().strftime('%H:%M:%S')} | {ip}:{port}\n"
        alert_msg += f"        Event: {event_type}\n"
        alert_msg += f"        Details: {details[:80]}\n"
        print(alert_msg, flush=True)


    def handle_client(self, client_sock, addr, port):
        ip = addr[0]
        with self.conn_lock:
             self.connections[port] += 1
        
        # For telnet, handle differently to avoid premature socket close
        if port == 23:
            try:
                self.log_activity(ip, port, "Telnet login attempt")
                self.handle_telnet_login(client_sock, ip)
            except Exception as e:
                self.log_activity(ip, port, f"Error: {str(e)}")
            finally:
                with self.conn_lock:
                    self.connections[port] = max(0, self.connections[port] - 1)
            return  # Don't close socket here, handle_telnet_login manages it
        elif port == 22:
                try:
                    self.log_activity(ip, port, "Telnet login attempt")
                    self.handle_ssh_client(client_sock, ip)
                except Exception as e:
                    self.log_activity(ip, port, f"Error: {str(e)}")
                finally:
                    with self.conn_lock:
                        self.connections[port] = max(0, self.connections[port] - 1)
                    return
        try:
            client_sock.settimeout(10)
            if port != 80:  # HTTP handled separately
                banner = self.banners.get(port, b"Unknown service\\r\\n")
                client_sock.send(banner)
                self.log_activity(ip,port, "banner sent")
            if port == 80:
                        print(f"\n[+] New HTTP connection: {ip}", flush=True)
                        raw_data = b""
                        while len(raw_data) < 8192:
                             try:
                                  chunk = client_sock.recv(4096)
                                  if not chunk:
                                       break
                                  raw_data += chunk
                                  if b"\r\n\r\n" in raw_data and len(raw_data) > 100:
                                       break
                             except socket.timeout:
                                  break
                             

                        http_request = raw_data.decode('utf-8', errors='ignore')
                        
                        # Check for X-Forwarded-For header
                        forwarded_ip = None
                        for line in http_request.split('\r\n'):
                            if line.lower().startswith('x-forwarded-for:'):
                                forwarded_ip = line.split(':')[1].strip().split(',')[0]
                                print(f"[+] X-Forwarded-For detected: {forwarded_ip}", flush=True)
                                break
                        
                        # Use forwarded IP if available, otherwise use real IP
                        log_ip = forwarded_ip if forwarded_ip else ip
                        
                        first_line = http_request.split('\r\n')[0] if '\r\n' in http_request else http_request[:50]
                        
                        self.log_activity(log_ip, port, "HTTP_REQUEST", first_line)
                        
                        ua_lines = [l for l in http_request.split('\r\n') if l.startswith('User-Agent:')]
                        if ua_lines:
                            self.log_activity(log_ip, port, "USER_AGENT", ua_lines[0][12:120])
    
                        if 'username=' in http_request or 'password=' in http_request:
                            self.log_activity(log_ip, port, "CREDENTIAL_ATTEMPT", http_request[:300])
                        client_sock.send(self.banners[80])
                        try:
                                client_sock.shutdown(socket.SHUT_RDWR)
                        except:
                                pass
                        return
            

            elif port == 21:
                 self.handle_ftp_session(client_sock,ip)         
            else:
                data= client_sock.recv(1024).decode('utf-8', errors='ignore')
                self.log_activity(ip,port,f"Received: {data}")
        except Exception as e:
            self.log_activity(ip, port, f"Error : {str(e)}")
        finally:
            with self.conn_lock:             
                self.connections[port] = max(0, self.connections[port] - 1 )
            
            client_sock.close()
            
    def listen_port(self, port):
        sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        print(f"[*] Listening on port {port}")
        while True:
            client_sock , addr = sock.accept()
            client_thread = threading.Thread(target=self.handle_client,args=(client_sock, addr, port))
            client_thread.start()
        sock.close()
    def docker_output_reader(self, docker_sock, client_connection):
        """Thread: Reads from Docker, Sends to Hacker"""
        try:
            docker_sock.settimeout(1)  # 1 second timeout to avoid hanging
            while True:
                try:
                    data = docker_sock.recv(4096)
                    if not data: 
                        break
                    format_output = data.replace(b'\n', b'\r\n')
                    client_connection.send(format_output)
                except socket.timeout:
                    continue  # Just retry on timeout
        except Exception as e:
            print(f"[*] Reader thread ended: {e}", flush=True)
    def start_docker_honeypot(self, client_sock, ip):
        # --- ESCAPE TRAP TOGGLES (Enable these to make it IMPOSSIBLE to exit) ---
        TRAP_ESCAPES = False # Set to False if you want real exit behavior
        client_sock.settimeout(300)
        try:
            client = docker.from_env()
            print(f" \n[*] Spawning container for {ip}...", flush=True)
        except Exception as e:
            print(f"\n[!] Docker error for {ip}: {e}", flush=True)
            client_sock.send(b"\r\nSystem error. Connection closed.\r\n")
            client_sock.close()
            return
        
        trap_path = Path.cwd()
        startup_cmd = "bash -c 'stty -echo; exec bash --noediting'"
        # container running
        try:
            container = client.containers.run(
                "honeypot/ubuntu-locked:latest", 
                startup_cmd,
                detach=True, 
                tty=True, 
                stdin_open=True,
                hostname="prod-db-01",
                mem_limit="128m",
                cpu_quota=50000,
                network_mode="none",
                pids_limit=50,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                read_only=True,
                tmpfs={"/tmp": "size=10m,mode=1777"},
                auto_remove=True
            )
        except Exception as e:
            print(f"\n [!] Container creation failed for {ip}: {e}", flush=True)
            client_sock.send(b"\r\nSystem initialization failed.\r\n")
            client_sock.close()
            return
        
        print(f"\n[*] Container started for {ip}", flush=True)
        try:
            # Use exec_run instead of attach_socket for proper socket support
            # This is the same pattern used successfully in start_docker_honeypot_ssh
            exec_result = container.exec_run(
                "/bin/bash -c 'stty -echo; exec bash --noediting'",
                stdin=True,
                stdout=True,
                stderr=True,
                tty=True,
                socket=True
            )
            docker_sock = exec_result.output._sock  # Get the actual socket
            
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) 
            client_sock.send(bytes([255,251,1]))
            client_sock.send(bytes([255, 251, 3]))
            client_sock.send(bytes([255,252,34]))
            client_sock.send(b"Connected to Ubuntu 22.04.4 LTS\r\n")
            
            t = threading.Thread(target=self.docker_output_reader, args=(docker_sock, client_sock))
            t.daemon = True
            t.start()
            command_buffer = b""
            escape_mode = False
            escape_buff = b""
            max_escape_buff = 8 
            while True:
                        hacker_input = client_sock.recv(1024)
                        if not hacker_input : break
                        clean_input = b""
                        for byte in hacker_input :
                            b = bytes([byte])
                            if TRAP_ESCAPES and byte == 3 :
                                 client_sock.send(b"\r\n^c\r\nroot@production-server:/#")
                                 command_buffer = b""
                                 continue
                            if TRAP_ESCAPES and byte == 26 :
                                 client_sock.send(b"\r\n[1]+  Stopped                 bash\r\nroot@production-server:/# ")
                                 command_buffer = b""
                                 continue
                            if TRAP_ESCAPES and byte == 4 :
                                client_sock.send(b"\r\nlogout\r\nConnection closed by foreign host.\r\n")
                                time.sleep(1)  # Dramatic pause
                                client_sock.send(b"Connected to Ubuntu 22.04.4 LTS\r\nroot@production-server:/# ")
                                command_buffer = b""
                                continue

                            
                            if escape_mode :
                                escape_buff += b
                                if b in b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ~" or len(escape_buff) > max_escape_buff:
                                      escape_mode = False
                                      escape_buff = b""
                                continue
                            if b == b"\x1b" :
                                 escape_mode = True
                                 escape_buff = b""
                                 continue      



                            if byte == 127 or byte == 8 :
                                if len(command_buffer) > 0:
                                    client_sock.send(b'\b \b')
                                    docker_sock.send(b'\x7f')
                                    command_buffer = command_buffer[:-1]
                                continue
                            if byte < 128:
                                    char = bytes([byte])
                                    if char == b'\n' or char == b'\r'  :
                                        client_sock.send(b'\r\n')
                                        docker_sock.send(b'\n')
                                        try:
                                             decoded_cmd = command_buffer.decode('utf-8', errors='ignore').strip()
                                             if decoded_cmd: 
                                                  self.log_activity(ip, 23, f"CMD: {decoded_cmd}")
                                        except:pass
                                        command_buffer = b""
                                    else:
                                        client_sock.send(char)
                                        docker_sock.send(char)
                                        command_buffer += char 

                        if clean_input:
                            if TRAP_ESCAPES and (b'\r' in clean_input or b'\n' in clean_input):
                                 cmd = command_buffer.decode('utf-8', errors='ignore').strip().lower()
                                 if cmd in ['exit','logout','bye','quit']:
                                      client_sock.send(b"\r\nlogout\r\nConnection closed by foreign host.\r\n")
                                      time.sleep(1)
                                      client_sock.send(b"Connected to Ubuntu 22.04.4 LTS\r\nroot@production-server:/#")
                                      command_buffer = b""
                                      continue



                            if b'\r' in clean_input or b'\n' in clean_input :
                                    client_sock.send(b'\r\n')
                                    docker_sock.send(b'\n')   
                            else:
                                    client_sock.send(clean_input)
                                    docker_sock.send(clean_input)   
                                        
                                    command_buffer += clean_input
                                    try:
                                       decoded_cmd = command_buffer.decode('utf-8',errors='ignore').strip()
                                       if decoded_cmd:
                                             self.log_activity(ip , 23 , f"CMD: {decoded_cmd}" )
                                    except : pass
                                    command_buffer = b""
        except Exception as e:
            print(f"\n[!] Docker session error for {ip}: {e}", flush=True)
            self.log_activity(ip, 23, f"DOCKER_ERROR: {str(e)}")
        finally:
            print(f"\n[*] Killing container for {ip}", flush=True)
            try:
                container.stop()
            except:
                pass
            try:
                client_sock.close()
            except:
                pass
              
def container_watchdog(container, timeout=300):
    time.sleep(timeout)
    try:
        container.stop(timeout=5)
        container.remove()
    except: pass


class SSHHoneypotInterface(paramiko.ServerInterface):

    def __init__(self, valid_users):
        self.valid_users = valid_users
        self.username = None
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
             return paramiko.OPEN_SUCCEEDED 
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        self.username = username
        if username in self.valid_users and self.valid_users[username] == password:
             return paramiko.AUTH_SUCCESSFUL 
        return paramiko.AUTH_FAILED
    def get_allowed_auths(self, username):
         return "password"
    def check_channel_pty_request(self, channel, term, width, height,
  pixelwidth, pixelheight, modes):
       return True
    
    def check_channel_shell_request(self, channel):
       return True
    


if __name__ == '__main__':
    hp = Honeypot()
    for port in hp.ports :
        thread= threading.Thread(target=hp.listen_port, args=(port,))
        thread.daemon = True
        thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n Stopping HoneyPot...")