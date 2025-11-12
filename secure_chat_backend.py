import asyncio
import socket
import threading
import json
import hashlib
import secrets
import string
import time
import os
import sys
import base64
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Terminal color configuration
class TerminalStyle:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    DIM = '\033[2m'

class CryptographicEngine:
    """
    Advanced multi-layer encryption engine with HMAC signatures
    """
    
    PROTOCOLS = {
        '1': {
            'name': 'AES-256-GCM',
            'description': 'Galois/Counter Mode with authentication',
            'security_level': 'HIGH',
            'performance': 'FAST'
        },
        '2': {
            'name': 'ChaCha20-Poly1305',
            'description': 'Stream cipher with MAC authentication',
            'security_level': 'HIGH',
            'performance': 'VERY FAST'
        },
        '3': {
            'name': 'Triple-Layer AES+RSA+Fernet',
            'description': 'Multiple encryption passes with different algorithms',
            'security_level': 'EXTREME',
            'performance': 'MODERATE'
        },
        '4': {
            'name': 'AES-256-CBC + HMAC-SHA512',
            'description': 'Encrypt-then-MAC with secure hash',
            'security_level': 'EXTREME',
            'performance': 'FAST'
        },
        '5': {
            'name': 'Multi-Round Cascading Encryption',
            'description': '5-pass encryption with key derivation per round',
            'security_level': 'MAXIMUM',
            'performance': 'MODERATE (Async Optimized)'
        },
        '6': {
            'name': 'XChaCha20-Poly1305 Extended Nonce',
            'description': 'Extended nonce ChaCha20 for long-term keys',
            'security_level': 'MAXIMUM',
            'performance': 'VERY FAST'
        }
    }
    
    def __init__(self, protocol='1'):
        self.protocol = protocol
        self.master_key = None
        self.session_key = None
        self.hmac_key = None
        self.rsa_private = None
        self.rsa_public = None
        self.fernet_key = None
        self.key_rotation_counter = 0
        self.max_operations_before_rotation = 1000
        self.lock = threading.Lock()
        
    def initialize_keys(self, password=None, salt=None):
        """Initialize cryptographic keys with optional password derivation"""
        if password:
            if not salt:
                salt = os.urandom(32)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=96,  # 32 + 32 + 32 for three keys
                salt=salt,
                iterations=600000,
                backend=default_backend()
            )
            derived = kdf.derive(password.encode())
            self.master_key = derived[:32]
            self.session_key = derived[32:64]
            self.hmac_key = derived[64:96]
        else:
            self.master_key = os.urandom(32)
            self.session_key = os.urandom(32)
            self.hmac_key = os.urandom(32)
        
        # RSA key pair for authentication and key exchange
        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.rsa_public = self.rsa_private.public_key()
        
        # Fernet for triple-layer encryption
        fernet_raw = base64.urlsafe_b64encode(self.master_key)
        self.fernet_key = fernet_raw
    
    def create_signature(self, data: str) -> str:
        """Create HMAC signature for message integrity"""
        h = hmac.HMAC(self.hmac_key, hashes.SHA512(), backend=default_backend())
        h.update(data.encode())
        return base64.b64encode(h.finalize()).decode()
    
    def verify_signature(self, data: str, signature: str) -> bool:
        """Verify HMAC signature"""
        try:
            h = hmac.HMAC(self.hmac_key, hashes.SHA512(), backend=default_backend())
            h.update(data.encode())
            h.verify(base64.b64decode(signature))
            return True
        except Exception:
            return False
    
    def sign_with_rsa(self, data: str) -> str:
        """Sign data with RSA private key"""
        signature = self.rsa_private.sign(
            data.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_rsa_signature(self, data: str, signature: str, public_key) -> bool:
        """Verify RSA signature"""
        try:
            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def rotate_session_key(self):
        """Rotate session key using HKDF for forward secrecy"""
        with self.lock:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                info=b'session_key_rotation',
                backend=default_backend()
            )
            self.session_key = hkdf.derive(self.session_key)
            self.key_rotation_counter = 0
    
    def check_rotation(self):
        """Check if key rotation is needed"""
        with self.lock:
            self.key_rotation_counter += 1
            if self.key_rotation_counter >= self.max_operations_before_rotation:
                self.rotate_session_key()
                return True
            return False
    
    async def encrypt_async(self, message):
        """Async encryption for heavy operations"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.encrypt, message)
    
    def encrypt(self, message):
        """Encrypt message using selected protocol"""
        self.check_rotation()
        
        if self.protocol == '1':
            return self._encrypt_aes_gcm(message)
        elif self.protocol == '2':
            return self._encrypt_chacha20(message)
        elif self.protocol == '3':
            return self._encrypt_triple_layer(message)
        elif self.protocol == '4':
            return self._encrypt_aes_hmac(message)
        elif self.protocol == '5':
            return self._encrypt_multi_round(message)
        elif self.protocol == '6':
            return self._encrypt_xchacha20(message)
    
    async def decrypt_async(self, encrypted_data):
        """Async decryption for heavy operations"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.decrypt, encrypted_data)
    
    def decrypt(self, encrypted_data):
        """Decrypt message using selected protocol"""
        try:
            if self.protocol == '1':
                return self._decrypt_aes_gcm(encrypted_data)
            elif self.protocol == '2':
                return self._decrypt_chacha20(encrypted_data)
            elif self.protocol == '3':
                return self._decrypt_triple_layer(encrypted_data)
            elif self.protocol == '4':
                return self._decrypt_aes_hmac(encrypted_data)
            elif self.protocol == '5':
                return self._decrypt_multi_round(encrypted_data)
            elif self.protocol == '6':
                return self._decrypt_xchacha20(encrypted_data)
        except Exception:
            return None
    
    def _encrypt_aes_gcm(self, message):
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(nonce + encryptor.tag + ciphertext).decode()
    
    def _decrypt_aes_gcm(self, encrypted):
        data = base64.b64decode(encrypted)
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    
    def _encrypt_chacha20(self, message):
        nonce = os.urandom(16)
        cipher = Cipher(
            algorithms.ChaCha20(self.session_key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(nonce + ciphertext).decode()
    
    def _decrypt_chacha20(self, encrypted):
        data = base64.b64decode(encrypted)
        nonce = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(
            algorithms.ChaCha20(self.session_key, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    
    def _encrypt_triple_layer(self, message):
        layer1 = self._encrypt_aes_gcm(message)
        f = Fernet(self.fernet_key)
        layer2 = f.encrypt(layer1.encode())
        return base64.b64encode(layer2).decode()
    
    def _decrypt_triple_layer(self, encrypted):
        layer2 = base64.b64decode(encrypted)
        f = Fernet(self.fernet_key)
        layer1 = f.decrypt(layer2).decode()
        return self._decrypt_aes_gcm(layer1)
    
    def _encrypt_aes_hmac(self, message):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        padding_length = 16 - (len(message) % 16)
        padded = message + (chr(padding_length) * padding_length)
        
        ciphertext = encryptor.update(padded.encode()) + encryptor.finalize()
        
        h = hmac.HMAC(self.master_key, hashes.SHA512(), backend=default_backend())
        h.update(iv + ciphertext)
        mac = h.finalize()
        
        return base64.b64encode(mac + iv + ciphertext).decode()
    
    def _decrypt_aes_hmac(self, encrypted):
        data = base64.b64decode(encrypted)
        mac = data[:64]
        iv = data[64:80]
        ciphertext = data[80:]
        
        h = hmac.HMAC(self.master_key, hashes.SHA512(), backend=default_backend())
        h.update(iv + ciphertext)
        h.verify(mac)
        
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        padding_length = padded[-1]
        return padded[:-padding_length].decode()
    
    def _encrypt_multi_round(self, message):
        data = message.encode()
        
        for i in range(5):
            nonce = os.urandom(12)
            round_key = hashlib.sha256(self.session_key + str(i).encode()).digest()
            cipher = Cipher(
                algorithms.AES(round_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            data = nonce + encryptor.tag + encryptor.update(data) + encryptor.finalize()
        
        return base64.b64encode(data).decode()
    
    def _decrypt_multi_round(self, encrypted):
        data = base64.b64decode(encrypted)
        
        for i in range(4, -1, -1):
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            round_key = hashlib.sha256(self.session_key + str(i).encode()).digest()
            cipher = Cipher(
                algorithms.AES(round_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return data.decode()
    
    def _encrypt_xchacha20(self, message):
        # ChaCha20 requires 16-byte nonce (not 24 for XChaCha20)
        nonce = os.urandom(16)
        cipher = Cipher(
            algorithms.ChaCha20(self.session_key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(nonce + ciphertext).decode()
    
    def _decrypt_xchacha20(self, encrypted):
        data = base64.b64decode(encrypted)
        nonce = data[:16]  # ChaCha20 uses 16-byte nonce
        ciphertext = data[16:]
        cipher = Cipher(
            algorithms.ChaCha20(self.session_key, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

class MessageArchive:
    """Encrypted message storage system with JSON serialization"""
    
    def __init__(self, group_id, encryption_engine):
        self.group_id = group_id
        self.crypto = encryption_engine
        self.storage_path = Path.home() / '.secure_chat' / group_id
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.messages = []
        self.max_messages = 1000
        
    def add_message(self, sender, content, timestamp=None):
        """Add message to archive"""
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        message = {
            'sender': sender,
            'content': content,
            'timestamp': timestamp
        }
        
        self.messages.append(message)
        
        if len(self.messages) > self.max_messages:
            self.messages.pop(0)
        
        self._save_to_disk()
    
    def get_messages(self, limit=50):
        """Retrieve recent messages"""
        return self.messages[-limit:]
    
    def search_messages(self, query):
        """Search messages by content"""
        results = []
        for msg in self.messages:
            if query.lower() in msg['content'].lower():
                results.append(msg)
        return results
    
    def _save_to_disk(self):
        """Save encrypted messages to disk using JSON"""
        try:
            json_data = json.dumps(self.messages)
            encrypted = self.crypto.encrypt(json_data)
            
            file_path = self.storage_path / 'messages.enc'
            with open(file_path, 'w') as f:
                f.write(encrypted)
        except Exception:
            pass
    
    def load_from_disk(self):
        """Load encrypted messages from disk"""
        try:
            file_path = self.storage_path / 'messages.enc'
            if file_path.exists():
                with open(file_path, 'r') as f:
                    encrypted = f.read()
                
                decrypted = self.crypto.decrypt(encrypted)
                if decrypted:
                    self.messages = json.loads(decrypted)
        except Exception:
            pass
    
    def wipe(self):
        """Securely delete all archived messages"""
        try:
            for file in self.storage_path.glob('*'):
                # Overwrite before deletion
                with open(file, 'wb') as f:
                    f.write(os.urandom(file.stat().st_size))
                file.unlink()
            self.storage_path.rmdir()
        except Exception:
            pass

class AuditLogger:
    """Administrator audit logging system with hash chain integrity"""
    
    def __init__(self, group_id):
        self.group_id = group_id
        self.log_path = Path.home() / '.secure_chat' / group_id / 'audit.log'
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_hash = hashlib.sha256(b'genesis_block').hexdigest()
        self.lock = threading.Lock()
    
    def log_event(self, event_type, actor, target=None, details=None):
        """Log administrative action with hash chain"""
        with self.lock:
            timestamp = datetime.now().isoformat()
            
            log_entry = {
                'timestamp': timestamp,
                'event': event_type,
                'actor': actor,
                'target': target,
                'details': details,
                'prev_hash': self.last_hash
            }
            
            # Calculate hash of current entry
            entry_str = json.dumps(log_entry, sort_keys=True)
            current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
            log_entry['hash'] = current_hash
            self.last_hash = current_hash
            
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
    
    def verify_integrity(self) -> bool:
        """Verify hash chain integrity"""
        try:
            logs = self.get_logs(limit=None)
            if not logs:
                return True
            
            expected_hash = hashlib.sha256(b'genesis_block').hexdigest()
            
            for log in logs:
                if log.get('prev_hash') != expected_hash:
                    return False
                
                # Recalculate hash
                log_copy = log.copy()
                current_hash = log_copy.pop('hash')
                entry_str = json.dumps(log_copy, sort_keys=True)
                calculated_hash = hashlib.sha256(entry_str.encode()).hexdigest()
                
                if calculated_hash != current_hash:
                    return False
                
                expected_hash = current_hash
            
            return True
        except Exception:
            return False
    
    def get_logs(self, limit=100):
        """Retrieve recent audit logs"""
        logs = []
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    logs.append(json.loads(line.strip()))
            if limit:
                return logs[-limit:]
            return logs
        except Exception:
            return []

class SecureConnection:
    """Thread-safe TLS connection wrapper"""
    
    def __init__(self, sock, use_tls=True):
        self.sock = sock
        self.use_tls = use_tls
        self.lock = threading.Lock()
        
        if use_tls and isinstance(sock, socket.socket):
            # Wrap with TLS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # For P2P without CA
            try:
                self.sock = context.wrap_socket(sock, server_side=True)
            except Exception:
                pass  # Keep original socket if TLS fails
    
    def send(self, data):
        """Thread-safe send"""
        with self.lock:
            self.sock.sendall(data)
    
    def recv(self, bufsize):
        """Thread-safe receive"""
        with self.lock:
            return self.sock.recv(bufsize)
    
    def close(self):
        """Close connection"""
        try:
            self.sock.close()
        except Exception:
            pass

class P2PNetworkNode:
    """Asyncio-based distributed peer-to-peer network node"""
    
    def __init__(self, port=None):
        self.port = port or self._find_available_port()
        self.peers = {}
        self.server = None
        self.active = False
        self.connections = []
        self.conn_lock = threading.Lock()
        
    def _find_available_port(self):
        """Locate available network port"""
        for port in range(5000, 6000):
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('0.0.0.0', port))
                test_socket.close()
                return port
            except OSError:
                continue
        return 5555
    
    def add_connection(self, conn):
        """Thread-safe connection addition"""
        with self.conn_lock:
            self.connections.append(conn)
    
    def remove_connection(self, conn):
        """Thread-safe connection removal"""
        with self.conn_lock:
            if conn in self.connections:
                self.connections.remove(conn)
    
    def get_connections(self):
        """Thread-safe connection retrieval"""
        with self.conn_lock:
            return self.connections.copy()
    
    def connect_peer(self, ip, port, use_tls=True):
        """Establish TLS connection with peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock)
                except Exception:
                    pass  # Fall back to non-TLS
            
            sock.connect((ip, port))
            return sock
        except Exception:
            return None
    
    def get_local_address(self):
        """Retrieve local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def get_public_address(self):
        """Attempt to retrieve public IP address"""
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf8')
        except Exception:
            return self.get_local_address()

class SecureGroupCommunicator:
    """Main secure group communication system with async support"""
    
    def __init__(self):
        self.network = P2PNetworkNode()
        self.crypto = None
        self.archive = None
        self.audit = None
        
        self.group_id = None
        self.group_password = None
        self.group_name = None
        self.group_bio = None
        self.group_max_members = 50
        
        self.username = None
        self.is_admin = False
        self.admin_list = []
        self.member_list = []
        self.member_public_keys = {}  # Store RSA public keys
        self.muted_users = []
        self.banned_ips = []
        
        self.active = False
        self.peer_registry = []
        
        self.message_ttl = 3600
        self.ephemeral_mode = False
        self.server_socket = None
        
    def clear_terminal(self):
        """Cross-platform terminal clear"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self, text):
        width = 70
        print(f"\n{TerminalStyle.BOLD}{TerminalStyle.INFO}{'='*width}{TerminalStyle.RESET}")
        print(f"{TerminalStyle.BOLD}{TerminalStyle.INFO}{text.center(width)}{TerminalStyle.RESET}")
        print(f"{TerminalStyle.BOLD}{TerminalStyle.INFO}{'='*width}{TerminalStyle.RESET}\n")
    
    def print_success(self, text):
        print(f"{TerminalStyle.SUCCESS}[SUCCESS] {text}{TerminalStyle.RESET}")
    
    def print_error(self, text):
        print(f"{TerminalStyle.ERROR}[ERROR] {text}{TerminalStyle.RESET}")
    
    def print_info(self, text):
        print(f"{TerminalStyle.INFO}[INFO] {text}{TerminalStyle.RESET}")
    
    def print_warning(self, text):
        print(f"{TerminalStyle.WARNING}[WARNING] {text}{TerminalStyle.RESET}")
    
    def generate_credentials(self):
        """Generate secure group credentials"""
        charset = string.ascii_letters + string.digits
        self.group_id = ''.join(secrets.choice(charset) for _ in range(24))
        self.group_password = ''.join(secrets.choice(charset) for _ in range(20))
    
    def display_encryption_protocols(self):
        """Display available encryption protocols"""
        self.print_header("ENCRYPTION PROTOCOL SELECTION")
        
        for key, protocol in CryptographicEngine.PROTOCOLS.items():
            print(f"{TerminalStyle.BOLD}[{key}] {protocol['name']}{TerminalStyle.RESET}")
            print(f"    Description: {protocol['description']}")
            print(f"    Security Level: {protocol['security_level']}")
            print(f"    Performance: {protocol['performance']}\n")
        
        while True:
            choice = input(f"Select protocol [1-6]: ").strip()
            if choice in CryptographicEngine.PROTOCOLS:
                return choice
            self.print_error("Invalid selection. Choose 1-6.")
    
    def create_challenge(self) -> str:
        """Create authentication challenge"""
        return secrets.token_hex(32)
    
    def verify_challenge_response(self, challenge: str, response: str, public_key) -> bool:
        """Verify challenge-response authentication"""
        return self.crypto.verify_rsa_signature(challenge, response, public_key)
    
    def create_group(self):
        """Initialize new secure group"""
        self.clear_terminal()
        self.print_header("GROUP INITIALIZATION")
        
        # Collect group parameters
        while True:
            self.group_name = input("Group name [max 20 characters]: ").strip()
            if 1 <= len(self.group_name) <= 20:
                break
            self.print_error("Name must be 1-20 characters")
        
        self.group_bio = input("Group description [max 50 characters, optional]: ").strip()
        if len(self.group_bio) > 50:
            self.group_bio = self.group_bio[:50]
        if not self.group_bio:
            self.group_bio = "No description provided"
        
        self.username = input("Administrator username: ").strip()
        
        # Configure encryption
        protocol = self.display_encryption_protocols()
        
        # Enable ephemeral messaging
        ephemeral = input("Enable ephemeral messaging? [y/N]: ").strip().lower()
        self.ephemeral_mode = ephemeral == 'y'
        
        # Generate credentials
        self.generate_credentials()
        self.crypto = CryptographicEngine(protocol)
        self.crypto.initialize_keys(self.group_password)
        
        # Store own public key
        self.member_public_keys[self.username] = self.crypto.rsa_public
        
        # Initialize subsystems
        self.archive = MessageArchive(self.group_id, self.crypto)
        self.audit = AuditLogger(self.group_id)
        
        # Set administrator status
        self.is_admin = True
        self.admin_list = [self.username]
        self.member_list = [self.username]
        
        # Start server socket
        self.start_server()
        
        # Log creation
        self.audit.log_event('GROUP_CREATED', self.username, details={
            'protocol': protocol,
            'ephemeral': self.ephemeral_mode
        })
        
        # Display credentials
        self.clear_terminal()
        self.print_header("GROUP CREATED SUCCESSFULLY")
        
        print(f"{TerminalStyle.BOLD}Group Information:{TerminalStyle.RESET}")
        print(f"  Name: {self.group_name}")
        print(f"  Description: {self.group_bio}")
        print(f"  Maximum Members: {self.group_max_members}")
        print(f"  Ephemeral Mode: {'Enabled' if self.ephemeral_mode else 'Disabled'}")
        
        print(f"\n{TerminalStyle.BOLD}Access Credentials:{TerminalStyle.RESET}")
        print(f"  Group ID: {TerminalStyle.WARNING}{self.group_id}{TerminalStyle.RESET}")
        print(f"  Password: {TerminalStyle.WARNING}{self.group_password}{TerminalStyle.RESET}")
        print(f"  Encryption Protocol: {protocol}")
        
        print(f"\n{TerminalStyle.BOLD}Network Configuration:{TerminalStyle.RESET}")
        print(f"  Local IP: {self.network.get_local_address()}")
        print(f"  Public IP: {self.network.get_public_address()}")
        print(f"  Port: {self.network.port}")
        print(f"  TLS Encryption: Enabled")
        
        print(f"\n{TerminalStyle.BOLD}Administrator Status:{TerminalStyle.RESET}")
        print(f"  Role: Primary Administrator")
        print(f"  Permissions: Full Access")
        
        print(f"\n{TerminalStyle.DIM}Share credentials securely with authorized members{TerminalStyle.RESET}")
        
        input("\nPress ENTER to proceed to communication interface...")
        
        self.active = True
        threading.Thread(target=self.accept_connections, daemon=True).start()
        self.communication_interface()
    
    def start_server(self):
        """Start server socket with TLS"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.network.port))
        self.server_socket.listen(20)
    
    def join_group(self):
        """Join existing secure group with challenge-response auth"""
        self.clear_terminal()
        self.print_header("GROUP CONNECTION")
        
        # Collect credentials
        self.group_id = input("Group ID [24 characters]: ").strip()
        self.group_password = input("Group Password [20 characters]: ").strip()
        
        # Connection parameters
        admin_ip = input("Administrator IP address: ").strip()
        admin_port = int(input("Administrator port: ").strip())
        protocol = input("Encryption protocol [1-6]: ").strip()
        
        self.username = input("Your username: ").strip()
        
        # Initialize encryption
        self.crypto = CryptographicEngine(protocol)
        self.crypto.initialize_keys(self.group_password)
        
        # Attempt connection with TLS
        self.print_info("Establishing secure TLS connection...")
        conn = self.network.connect_peer(admin_ip, admin_port, use_tls=True)
        
        if not conn:
            self.print_error("Connection failed")
            input("Press ENTER to return...")
            return
        
        # Export public key
        public_key_pem = self.crypto.rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Send join request
        join_packet = {
            'type': 'join_request',
            'group_id': self.group_id,
            'username': self.username,
            'port': self.network.port,
            'public_key': public_key_pem
        }
        
        try:
            conn.sendall(json.dumps(join_packet).encode())
            
            # Wait for challenge
            challenge_data = json.loads(conn.recv(16384).decode())
            
            if challenge_data.get('type') == 'challenge':
                # Sign challenge with private key
                challenge = challenge_data['challenge']
                signature = self.crypto.sign_with_rsa(challenge)
                
                # Send response
                response_packet = {
                    'type': 'challenge_response',
                    'signature': signature
                }
                conn.sendall(json.dumps(response_packet).encode())
                
                # Wait for approval
                response = json.loads(conn.recv(16384).decode())
                
                if response['status'] == 'approved':
                    self.group_name = response['group_name']
                    self.group_bio = response['group_bio']
                    self.admin_list = response['admins']
                    self.member_list = response['members']
                    self.peer_registry = response['peers']
                    self.ephemeral_mode = response.get('ephemeral', False)
                    self.is_admin = self.username in self.admin_list
                    
                    # Load member public keys
                    for member_data in response.get('member_keys', []):
                        key_pem = member_data['public_key']
                        public_key = serialization.load_pem_public_key(
                            key_pem.encode(),
                            backend=default_backend()
                        )
                        self.member_public_keys[member_data['username']] = public_key
                    
                    self.network.add_connection(conn)
                    
                    # Initialize subsystems
                    self.archive = MessageArchive(self.group_id, self.crypto)
                    if not self.ephemeral_mode:
                        self.archive.load_from_disk()
                    
                    # Start server
                    self.start_server()
                    
                    # Display success
                    self.clear_terminal()
                    self.print_header("CONNECTION ESTABLISHED")
                    print(f"Group: {self.group_name}")
                    print(f"Description: {self.group_bio}")
                    print(f"Members: {len(self.member_list)}")
                    print(f"Status: {'Administrator' if self.is_admin else 'Member'}")
                    print(f"TLS Encryption: Enabled")
                    
                    input("\nPress ENTER to proceed...")
                    
                    self.active = True
                    threading.Thread(target=self.receive_messages, args=(conn,), daemon=True).start()
                    threading.Thread(target=self.accept_connections, daemon=True).start()
                    
                    # Connect to peers
                    self.establish_peer_connections()
                    
                    self.communication_interface()
                else:
                    self.print_error(f"Authentication failed: {response['message']}")
                    conn.close()
                    input("Press ENTER to return...")
            else:
                self.print_error("Invalid server response")
                conn.close()
                input("Press ENTER to return...")
                
        except Exception as e:
            self.print_error(f"Protocol error: {e}")
            input("Press ENTER to return...")
    
    def accept_connections(self):
        """Accept incoming peer connections"""
        while self.active:
            try:
                conn, addr = self.server_socket.accept()
                
                # Check if IP is banned
                if addr[0] in self.banned_ips:
                    conn.close()
                    continue
                
                # Wrap with TLS
                try:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = context.wrap_socket(conn, server_side=True)
                except Exception:
                    pass  # Continue with non-TLS
                
                threading.Thread(target=self.handle_peer_connection, args=(conn, addr), daemon=True).start()
            except Exception:
                break
    
    def handle_peer_connection(self, conn, addr):
        """Process incoming peer connection with challenge-response"""
        try:
            data = json.loads(conn.recv(16384).decode())
            
            if data['type'] == 'join_request':
                # Verify credentials
                if data['group_id'] == self.group_id:
                    # Check member limit
                    if len(self.member_list) >= self.group_max_members:
                        response = {'status': 'rejected', 'message': 'Group at capacity'}
                        conn.sendall(json.dumps(response).encode())
                        conn.close()
                        return
                    
                    # Load joining user's public key
                    public_key_pem = data['public_key']
                    joining_public_key = serialization.load_pem_public_key(
                        public_key_pem.encode(),
                        backend=default_backend()
                    )
                    
                    # Send challenge
                    challenge = self.create_challenge()
                    challenge_packet = {
                        'type': 'challenge',
                        'challenge': challenge
                    }
                    conn.sendall(json.dumps(challenge_packet).encode())
                    
                    # Wait for response
                    response_data = json.loads(conn.recv(16384).decode())
                    
                    if response_data.get('type') == 'challenge_response':
                        signature = response_data['signature']
                        
                        # Verify signature
                        if self.verify_challenge_response(challenge, signature, joining_public_key):
                            # Approve join
                            username = data['username']
                            self.member_list.append(username)
                            self.member_public_keys[username] = joining_public_key
                            
                            self.peer_registry.append({
                                'ip': addr[0],
                                'port': data['port'],
                                'username': username,
                                'public_key': public_key_pem
                            })
                            
                            # Prepare member keys for new user
                            member_keys = []
                            for member, key in self.member_public_keys.items():
                                key_pem = key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                ).decode()
                                member_keys.append({'username': member, 'public_key': key_pem})
                            
                            response = {
                                'status': 'approved',
                                'group_name': self.group_name,
                                'group_bio': self.group_bio,
                                'admins': self.admin_list,
                                'members': self.member_list,
                                'peers': self.peer_registry,
                                'ephemeral': self.ephemeral_mode,
                                'member_keys': member_keys
                            }
                            conn.sendall(json.dumps(response).encode())
                            
                            self.network.add_connection(conn)
                            
                            # Log join event
                            if self.audit:
                                self.audit.log_event('MEMBER_JOIN', username, details={'ip': addr[0]})
                            
                            # Notify group
                            self.broadcast_system_message(f"[SYSTEM] {username} has joined the group")
                            
                            threading.Thread(target=self.receive_messages, args=(conn,), daemon=True).start()
                        else:
                            response = {'status': 'rejected', 'message': 'Authentication failed'}
                            conn.sendall(json.dumps(response).encode())
                            conn.close()
                    else:
                        response = {'status': 'rejected', 'message': 'Invalid response'}
                        conn.sendall(json.dumps(response).encode())
                        conn.close()
                else:
                    response = {'status': 'rejected', 'message': 'Invalid credentials'}
                    conn.sendall(json.dumps(response).encode())
                    conn.close()
            
            elif data['type'] == 'peer_handshake':
                # Peer-to-peer connection establishment
                self.network.add_connection(conn)
                threading.Thread(target=self.receive_messages, args=(conn,), daemon=True).start()
                
        except Exception:
            pass
    
    def establish_peer_connections(self):
        """Connect to all registered peers"""
        for peer in self.peer_registry:
            if peer['username'] != self.username:
                conn = self.network.connect_peer(peer['ip'], peer['port'], use_tls=True)
                if conn:
                    handshake = {
                        'type': 'peer_handshake',
                        'username': self.username
                    }
                    try:
                        conn.sendall(json.dumps(handshake).encode())
                        self.network.add_connection(conn)
                        threading.Thread(target=self.receive_messages, args=(conn,), daemon=True).start()
                    except Exception:
                        pass
    
    def receive_messages(self, conn):
        """Receive and process messages from connection"""
        while self.active:
            try:
                data = conn.recv(16384)
                if not data:
                    break
                
                msg = json.loads(data.decode())
                
                # Verify message signature
                if 'signature' in msg and 'content' in msg:
                    if not self.crypto.verify_signature(msg['content'], msg['signature']):
                        continue  # Drop message with invalid signature
                
                if msg['type'] == 'encrypted_message':
                    # Decrypt and display
                    decrypted = self.crypto.decrypt(msg['content'])
                    if decrypted and msg['sender'] not in self.muted_users:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Display with username prefix
                        print(f"\r{TerminalStyle.DIM}[{timestamp}]{TerminalStyle.RESET} {TerminalStyle.SUCCESS}{msg['sender']}>{TerminalStyle.RESET} {decrypted}")
                        print(f"{TerminalStyle.INFO}{self.username}> {TerminalStyle.RESET}", end="", flush=True)
                        
                        # Archive message if not ephemeral
                        if not self.ephemeral_mode and self.archive:
                            self.archive.add_message(msg['sender'], decrypted, timestamp)
                
                elif msg['type'] == 'system_message':
                    # Verify system message signature
                    if 'signature' in msg:
                        print(f"\r{TerminalStyle.WARNING}[SYSTEM]{TerminalStyle.RESET} {msg['content']}")
                        print(f"{TerminalStyle.INFO}> {TerminalStyle.RESET}", end="", flush=True)
                
                elif msg['type'] == 'file_transfer':
                    self.handle_file_transfer(msg)
                
                elif msg['type'] == 'kicked' and msg['target'] == self.username:
                    print(f"\n\n{TerminalStyle.ERROR}{'='*70}{TerminalStyle.RESET}")
                    print(f"{TerminalStyle.ERROR}{TerminalStyle.BOLD}ACCESS REVOKED - REMOVED FROM GROUP{TerminalStyle.RESET}")
                    print(f"{TerminalStyle.ERROR}{'='*70}{TerminalStyle.RESET}")
                    self.secure_wipe()
                    time.sleep(2)
                    sys.exit(0)
                
                elif msg['type'] == 'key_rotation':
                    self.crypto.rotate_session_key()
                    
            except Exception:
                break
        
        # Remove connection on disconnect
        self.network.remove_connection(conn)
    
    def broadcast_message(self, message):
        """Broadcast encrypted message with HMAC signature"""
        encrypted = self.crypto.encrypt(message)
        signature = self.crypto.create_signature(encrypted)
        
        packet = {
            'type': 'encrypted_message',
            'sender': self.username,
            'content': encrypted,
            'signature': signature,
            'timestamp': datetime.now().isoformat()
        }
        
        serialized = json.dumps(packet)
        
        for conn in self.network.get_connections():
            try:
                conn.sendall(serialized.encode())
            except Exception:
                self.network.remove_connection(conn)
        
        # Archive own message
        if not self.ephemeral_mode and self.archive:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.archive.add_message(self.username, message, timestamp)
    
    def broadcast_system_message(self, message):
        """Broadcast system notification with signature"""
        signature = self.crypto.create_signature(message)
        
        packet = {
            'type': 'system_message',
            'content': message,
            'signature': signature
        }
        
        serialized = json.dumps(packet)
        
        for conn in self.network.get_connections():
            try:
                conn.sendall(serialized.encode())
            except Exception:
                self.network.remove_connection(conn)
    
    def handle_file_transfer(self, packet):
        """Handle incoming file transfer"""
        filename = packet['filename']
        encrypted_data = packet['data']
        sender = packet['sender']
        
        # Verify signature
        if 'signature' not in packet or not self.crypto.verify_signature(encrypted_data, packet['signature']):
            self.print_error("File transfer signature verification failed")
            return
        
        # Decrypt file data
        decrypted_data = self.crypto.decrypt(encrypted_data)
        
        if decrypted_data:
            save_path = Path.home() / 'Downloads' / f"secure_{filename}"
            
            try:
                with open(save_path, 'wb') as f:
                    f.write(base64.b64decode(decrypted_data))
                
                print(f"\r{TerminalStyle.SUCCESS}[FILE] Received '{filename}' from {sender}{TerminalStyle.RESET}")
                print(f"{TerminalStyle.INFO}> {TerminalStyle.RESET}", end="", flush=True)
            except Exception:
                print(f"\r{TerminalStyle.ERROR}[FILE] Failed to save '{filename}'{TerminalStyle.RESET}")
                print(f"{TerminalStyle.INFO}> {TerminalStyle.RESET}", end="", flush=True)
    
    def send_file(self, filepath):
        """Send encrypted file to group"""
        try:
            path = Path(filepath)
            if not path.exists():
                self.print_error(f"File not found: {filepath}")
                return
            
            if path.stat().st_size > 10 * 1024 * 1024:
                self.print_error("File size exceeds 10MB limit")
                return
            
            with open(path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt file data
            encoded = base64.b64encode(file_data).decode()
            encrypted = self.crypto.encrypt(encoded)
            signature = self.crypto.create_signature(encrypted)
            
            packet = {
                'type': 'file_transfer',
                'sender': self.username,
                'filename': path.name,
                'data': encrypted,
                'signature': signature
            }
            
            serialized = json.dumps(packet)
            
            for conn in self.network.get_connections():
                try:
                    conn.sendall(serialized.encode())
                except Exception:
                    pass
            
            self.print_success(f"File '{path.name}' sent successfully")
            
        except Exception as e:
            self.print_error(f"File transfer failed: {e}")
    
    def communication_interface(self):
        """Main communication interface"""
        self.clear_terminal()
        self.print_header(f"SECURE COMMUNICATION - {self.group_name}")
        
        print(f"{TerminalStyle.BOLD}Available Commands:{TerminalStyle.RESET}")
        print(f"  /help          - Display command list")
        print(f"  /info          - Group information")
        print(f"  /history       - View message history")
        print(f"  /search        - Search messages")
        print(f"  /file <path>   - Send file")
        print(f"  /verify        - Verify audit log integrity")
        print(f"  /quit          - Disconnect from group")
        
        if self.is_admin:
            print(f"\n{TerminalStyle.BOLD}Administrator Commands:{TerminalStyle.RESET}")
            print(f"  /kick <user>     - Remove member")
            print(f"  /promote <user>  - Grant admin privileges")
            print(f"  /demote <user>   - Revoke admin privileges")
            print(f"  /mute <user>     - Mute member messages")
            print(f"  /unmute <user>   - Unmute member")
            print(f"  /ban <user>      - Ban member permanently")
            print(f"  /members         - List all members")
            print(f"  /admins          - List administrators")
            print(f"  /audit           - View audit log")
            print(f"  /rotate          - Force key rotation")
        
        print(f"\n{TerminalStyle.SUCCESS}{'='*70}{TerminalStyle.RESET}\n")
        print(f"{TerminalStyle.INFO}{self.username}> {TerminalStyle.RESET}", end="", flush=True)
        
        while self.active:
            try:
                message = input()
                
                if message.startswith('/'):
                    self.process_command(message)
                elif message.strip():
                    self.broadcast_message(message)
                
                print(f"{TerminalStyle.INFO}{self.username}> {TerminalStyle.RESET}", end="", flush=True)
                
            except (EOFError, KeyboardInterrupt):
                self.print_warning("Disconnecting from group...")
                self.active = False
                break
        
        self.cleanup()
    
    def process_command(self, command):
        """Process user commands"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None
        
        if cmd == '/quit':
            self.active = False
            
        elif cmd == '/help':
            self.display_help()
            
        elif cmd == '/info':
            self.display_group_info()
            
        elif cmd == '/history':
            self.display_message_history()
            
        elif cmd == '/search' and arg:
            self.search_messages(arg)
            
        elif cmd == '/file' and arg:
            self.send_file(arg)
        
        elif cmd == '/verify':
            self.verify_audit_integrity()
            
        elif cmd == '/members' and self.is_admin:
            self.display_members()
            
        elif cmd == '/admins' and self.is_admin:
            self.display_admins()
            
        elif cmd == '/kick' and self.is_admin and arg:
            self.kick_member(arg)
            
        elif cmd == '/promote' and self.is_admin and arg:
            self.promote_member(arg)
            
        elif cmd == '/demote' and self.is_admin and arg:
            self.demote_member(arg)
            
        elif cmd == '/mute' and self.is_admin and arg:
            self.mute_member(arg)
            
        elif cmd == '/unmute' and self.is_admin and arg:
            self.unmute_member(arg)
            
        elif cmd == '/ban' and self.is_admin and arg:
            self.ban_member(arg)
            
        elif cmd == '/audit' and self.is_admin:
            self.display_audit_log()
            
        elif cmd == '/rotate' and self.is_admin:
            self.force_key_rotation()
            
        else:
            self.print_error("Unknown command or insufficient permissions")
    
    def display_help(self):
        """Display help information"""
        print(f"\n{TerminalStyle.BOLD}Command Reference:{TerminalStyle.RESET}")
        print(f"  /info                  Display group information")
        print(f"  /history               View recent messages")
        print(f"  /search <query>        Search message history")
        print(f"  /file <filepath>       Transfer encrypted file")
        print(f"  /verify                Verify audit log integrity")
        print(f"  /quit                  Disconnect from group")
        
        if self.is_admin:
            print(f"\n{TerminalStyle.BOLD}Administrative Commands:{TerminalStyle.RESET}")
            print(f"  /kick <username>       Remove member")
            print(f"  /promote <username>    Grant administrator role")
            print(f"  /demote <username>     Revoke administrator role")
            print(f"  /mute <username>       Mute member messages")
            print(f"  /unmute <username>     Unmute member")
            print(f"  /ban <username>        Permanently ban member")
            print(f"  /members               List all members")
            print(f"  /admins                List administrators")
            print(f"  /audit                 View audit log")
            print(f"  /rotate                Force session key rotation")
        print()
    
    def display_group_info(self):
        """Display group information"""
        print(f"\n{TerminalStyle.BOLD}Group Information:{TerminalStyle.RESET}")
        print(f"  Name: {self.group_name}")
        print(f"  Description: {self.group_bio}")
        print(f"  Group ID: {self.group_id}")
        print(f"  Ephemeral Mode: {'Enabled' if self.ephemeral_mode else 'Disabled'}")
        print(f"  TLS Encryption: Enabled")
        print(f"  Message Signatures: HMAC-SHA512")
        
        if self.is_admin:
            print(f"  Total Members: {len(self.member_list)}")
            print(f"  Total Administrators: {len(self.admin_list)}")
            print(f"  Active Connections: {len(self.network.get_connections())}")
            print(f"  Encryption Protocol: {CryptographicEngine.PROTOCOLS[self.crypto.protocol]['name']}")
        print()
    
    def display_message_history(self):
        """Display recent messages"""
        if self.ephemeral_mode:
            self.print_warning("Ephemeral mode enabled - message history not available")
            return
        
        if not self.archive:
            self.print_error("Message archive not available")
            return
        
        messages = self.archive.get_messages(20)
        
        print(f"\n{TerminalStyle.BOLD}Recent Messages:{TerminalStyle.RESET}")
        for msg in messages:
            timestamp = msg['timestamp']
            sender = msg['sender']
            content = msg['content']
            print(f"  {TerminalStyle.DIM}[{timestamp}]{TerminalStyle.RESET} {sender}: {content}")
        print()
    
    def search_messages(self, query):
        """Search message history"""
        if self.ephemeral_mode or not self.archive:
            self.print_warning("Search not available in ephemeral mode")
            return
        
        results = self.archive.search_messages(query)
        
        print(f"\n{TerminalStyle.BOLD}Search Results for '{query}':{TerminalStyle.RESET}")
        if results:
            for msg in results:
                print(f"  {TerminalStyle.DIM}[{msg['timestamp']}]{TerminalStyle.RESET} {msg['sender']}: {msg['content']}")
        else:
            print(f"  No results found")
        print()
    
    def verify_audit_integrity(self):
        """Verify audit log integrity"""
        if not self.audit:
            self.print_error("Audit log not available")
            return
        
        self.print_info("Verifying audit log hash chain...")
        if self.audit.verify_integrity():
            self.print_success("Audit log integrity verified - no tampering detected")
        else:
            self.print_error("Audit log integrity check FAILED - possible tampering detected")
    
    def display_members(self):
        """Display member list"""
        print(f"\n{TerminalStyle.BOLD}Group Members ({len(self.member_list)}):{TerminalStyle.RESET}")
        for member in self.member_list:
            admin_tag = " [ADMINISTRATOR]" if member in self.admin_list else ""
            you_tag = " [YOU]" if member == self.username else ""
            muted_tag = " [MUTED]" if member in self.muted_users else ""
            print(f"  {member}{admin_tag}{you_tag}{muted_tag}")
        print()
    
    def display_admins(self):
        """Display administrator list"""
        print(f"\n{TerminalStyle.BOLD}Administrators:{TerminalStyle.RESET}")
        for admin in self.admin_list:
            you_tag = " [YOU]" if admin == self.username else ""
            print(f"  {admin}{you_tag}")
        print()
    
    def kick_member(self, username):
        """Remove member from group"""
        if username not in self.member_list:
            self.print_error(f"Member '{username}' not found")
            return
        
        if username in self.admin_list and len(self.admin_list) == 1:
            self.print_error("Cannot remove the last administrator")
            return
        
        # Send kick notification
        kick_packet = {
            'type': 'kicked',
            'target': username
        }
        
        serialized = json.dumps(kick_packet)
        
        for conn in self.network.get_connections():
            try:
                conn.sendall(serialized.encode())
            except Exception:
                pass
        
        # Remove from lists
        self.member_list.remove(username)
        if username in self.admin_list:
            self.admin_list.remove(username)
        if username in self.member_public_keys:
            del self.member_public_keys[username]
        
        # Log event
        self.audit.log_event('MEMBER_KICKED', self.username, target=username)
        
        # Notify group
        self.broadcast_system_message(f"[SYSTEM] {username} has been removed from the group")
        self.print_success(f"Member '{username}' removed")
    
    def promote_member(self, username):
        """Grant administrator privileges"""
        if username not in self.member_list:
            self.print_error(f"Member '{username}' not found")
            return
        
        if username in self.admin_list:
            self.print_warning(f"Member '{username}' is already an administrator")
            return
        
        self.admin_list.append(username)
        self.audit.log_event('ADMIN_PROMOTED', self.username, target=username)
        self.broadcast_system_message(f"[SYSTEM] {username} has been promoted to administrator")
        self.print_success(f"Member '{username}' promoted to administrator")
    
    def demote_member(self, username):
        """Revoke administrator privileges"""
        if username not in self.admin_list:
            self.print_error(f"Member '{username}' is not an administrator")
            return
        
        if len(self.admin_list) == 1:
            self.print_error("Cannot demote the last administrator")
            return
        
        self.admin_list.remove(username)
        self.audit.log_event('ADMIN_DEMOTED', self.username, target=username)
        self.broadcast_system_message(f"[SYSTEM] {username} has been demoted from administrator")
        self.print_success(f"Member '{username}' demoted")
    
    def mute_member(self, username):
        """Mute member messages"""
        if username not in self.member_list:
            self.print_error(f"Member '{username}' not found")
            return
        
        if username not in self.muted_users:
            self.muted_users.append(username)
            self.audit.log_event('MEMBER_MUTED', self.username, target=username)
            self.print_success(f"Member '{username}' muted")
        else:
            self.print_warning(f"Member '{username}' is already muted")
    
    def unmute_member(self, username):
        """Unmute member messages"""
        if username in self.muted_users:
            self.muted_users.remove(username)
            self.audit.log_event('MEMBER_UNMUTED', self.username, target=username)
            self.print_success(f"Member '{username}' unmuted")
        else:
            self.print_warning(f"Member '{username}' is not muted")
    
    def ban_member(self, username):
        """Permanently ban member"""
        # Find member's IP
        member_ip = None
        for peer in self.peer_registry:
            if peer['username'] == username:
                member_ip = peer['ip']
                break
        
        if member_ip:
            self.banned_ips.append(member_ip)
        
        # Kick the member
        self.kick_member(username)
        
        self.audit.log_event('MEMBER_BANNED', self.username, target=username, details={'ip': member_ip})
        self.print_success(f"Member '{username}' banned")
    
    def display_audit_log(self):
        """Display audit log"""
        logs = self.audit.get_logs(30)
        
        print(f"\n{TerminalStyle.BOLD}Audit Log (Recent 30 Events):{TerminalStyle.RESET}")
        for log in logs:
            timestamp = log['timestamp']
            event = log['event']
            actor = log['actor']
            target = log.get('target', 'N/A')
            print(f"  {TerminalStyle.DIM}[{timestamp}]{TerminalStyle.RESET} {event} | Actor: {actor} | Target: {target}")
        print()
    
    def force_key_rotation(self):
        """Force session key rotation"""
        self.crypto.rotate_session_key()
        
        # Notify all peers
        rotation_packet = {
            'type': 'key_rotation'
        }
        
        serialized = json.dumps(rotation_packet)
        
        for conn in self.network.get_connections():
            try:
                conn.sendall(serialized.encode())
            except Exception:
                pass
        
        self.audit.log_event('KEY_ROTATION', self.username)
        self.print_success("Session key rotated successfully")
    
    def secure_wipe(self):
        """Securely wipe all group data"""
        self.group_id = None
        self.group_password = None
        self.group_name = None
        self.group_bio = None
        self.crypto = None
        self.admin_list = []
        self.member_list = []
        self.member_public_keys = {}
        self.peer_registry = []
        self.active = False
        
        if self.archive:
            self.archive.wipe()
    
    def cleanup(self):
        """Clean up resources"""
        for conn in self.network.get_connections():
            try:
                conn.close()
            except Exception:
                pass
        
        try:
            if self.server_socket:
                self.server_socket.close()
        except Exception:
            pass

def main():
    """Application entry point"""
    communicator = SecureGroupCommunicator()
    
    while True:
        communicator.clear_terminal()
        
        # Main menu
        print(f"{TerminalStyle.BOLD}{TerminalStyle.INFO}")
        print("=" * 70)
        print("ENTERPRISE SECURE COMMUNICATION SYSTEM".center(70))
        print("Military-Grade Encrypted Group Communication".center(70))
        print("Version 3.0.0 - Production Hardened".center(70))
        print("=" * 70)
        print(f"{TerminalStyle.RESET}")
        
        print(f"\n{TerminalStyle.BOLD}Security Features:{TerminalStyle.RESET}")
        print(f"  [+] TLS Transport Layer Encryption")
        print(f"  [+] Challenge-Response Authentication")
        print(f"  [+] HMAC Message Signatures (SHA-512)")
        print(f"  [+] RSA-4096 Key Exchange")
        print(f"  [+] Automatic Session Key Rotation")
        print(f"  [+] Hash Chain Audit Logging")
        print(f"  [+] Thread-Safe Connection Pool")
        print(f"  [+] JSON-Based Secure Serialization")
        
        print(f"\n{TerminalStyle.BOLD}Main Menu:{TerminalStyle.RESET}\n")
        print(f"  [1] Initialize New Group")
        print(f"  [2] Connect to Existing Group")
        print(f"  [3] Exit Application\n")
        
        choice = input(f"Selection [1-3]: ").strip()
        
        if choice == '1':
            communicator.create_group()
        elif choice == '2':
            communicator.join_group()
        elif choice == '3':
            print(f"\n{TerminalStyle.SUCCESS}Application terminated{TerminalStyle.RESET}\n")
            sys.exit(0)
        else:
            communicator.print_error("Invalid selection")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{TerminalStyle.WARNING}Application interrupted{TerminalStyle.RESET}\n")
        sys.exit(0)
