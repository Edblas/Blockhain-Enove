# Blockhain-Enove
A new blockchain, proof-of-work, with open source. Help us spread awareness and increase network security.

import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import ecdsa
import hashlib
import time
import pyperclip
import threading
import socket
import json

class Block:
    """Classe que representa um bloco na blockchain."""
    def __init__(self, index, previous_hash, timestamp, data, nonce, hash, miner):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = hash
        self.miner = miner  # Atributo para registrar o minerador

class KeyVault:
    """Classe para gerenciar chaves privadas e públicas."""
    def __init__(self):
        self.keys = {}

    def store_key(self, public_key, private_key):
        """Armazena uma chave pública e sua correspondente chave privada."""
        self.keys[public_key] = private_key

    def retrieve_key(self, public_key):
        """Recupera a chave privada correspondente a uma chave pública."""
        return self.keys.get(public_key)

class Blockchain:
    """Classe que representa a blockchain."""
    def __init__(self):
        self.blocks = []
        self.key_vault = KeyVault()
        self.miner_saldos = {}
        self.reward = 25  # Recompensa inicial de 25 moedas
        self.create_genesis_block()

    def create_genesis_block(self):
        """Cria o bloco gênese e o adiciona à blockchain."""
        genesis_block = Block(0, "0", time.time(), "Bloco Gênese", 0, "0", "Genesis")
        self.blocks.append(genesis_block)

    def calculate_hash(self, index, previous_hash, timestamp, data, nonce):
        """Calcula o hash de um bloco."""
        value = f"{index}{previous_hash}{timestamp}{data}{nonce}".encode()
        return hashlib.sha256(value).hexdigest()

    def add_block(self, new_block):
        """Adiciona um bloco à blockchain após validação."""
        self.blocks.append(new_block)

    def sign_message(self, private_key, message):
        """Assina uma mensagem com a chave privada."""
        if private_key is None:
            raise ValueError("Chave privada não pode ser None.")
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key))
        return sk.sign(message.encode())

    def get_chain_info(self):
        """Retorna informações sobre a blockchain."""
        chain_info = ""
        for block in self.blocks:
            chain_info += (f"Índice: {block.index}\n"
                           f"Hash Anterior: {block.previous_hash}\n"
                           f"Timestamp: {block.timestamp}\n"
                           f"Dados: {block.data}\n"
                           f"Nonce: {block.nonce}\n"
                           f"Hash: {block.hash}\n"
                           f"Miner: {block.miner}\n\n")  # Adiciona informações do minerador
        return chain_info

    def get_reward(self):
        """Calcula a recompensa do bloco com base na lógica de halving."""
        halving_interval = 210_000  # A cada 210.000 blocos
        return self.reward if (len(self.blocks) // halving_interval) % 2 == 0 else self.reward // 2

class BlockchainApp:
    """Classe que representa a interface do aplicativo de blockchain."""
    def __init__(self):
        self.blockchain = Blockchain()
        self.miner_address = ""
        self.is_mining = False
        self.public_key_hex = None
        self.private_key_hex = None
        self.window = tk.Tk()
        self.window.title("Enove Blockchain")
        self.window.geometry("600x600") 

        tk.Label(self.window, text="Endereço do Minerador:").pack(pady=5)
        self.miner_address_label = tk.Label(self.window, text=self.miner_address)
        self.miner_address_label.pack(pady=5)

        tk.Button(self.window, text="Definir Endereço do Minerador", command=self.set_miner_address).pack(pady=5)
        tk.Button(self.window, text="Iniciar Mineração P2P", command=self.start_mining_p2p).pack(pady=5)
        tk.Button(self.window, text="Parar Mineração", command=self.stop_mining).pack(pady=5)  # Botão para parar a mineração
        tk.Button(self.window, text="Criar Carteira", command=self.create_wallet).pack(pady=5)
        tk.Button(self.window, text="Ver Saldo", command=self.view_balance).pack(pady=5)
        tk.Button(self.window, text="Ver Blockchain", command=self.view_blockchain).pack(pady=5)

        self.mining_status_label = tk.Label(self.window, text="Status: Aguardando mineração...")
        self.mining_status_label.pack(pady=(20, 0))

        self.start_p2p_server()  # Inicia o servidor P2P

    def set_miner_address(self):
        """Define o endereço do minerador.""" 
        address = simpledialog.askstring("Endereço do Minerador", "Insira seu endereço de minerador:")
        if address:
            # Verifica se a chave pública existe no KeyVault
            if self.blockchain.key_vault.retrieve_key(address) is not None:
                self.miner_address = address
                self.miner_address_label.config(text=self.miner_address)
            else:
                messagebox.showerror("Erro", "Chave pública não encontrada no sistema. Por favor, crie uma carteira.")

    def start_p2p_server(self):
        """Inicia o servidor P2P para comunicação entre mineradores.""" 
        self.server_thread = threading.Thread(target=self.p2p_server)
        self.server_thread.start()

    def p2p_server(self):
        """Servidor para aceitar conexões de outros nós na rede.""" 
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 5000))  # Escuta na porta 5000
        server_socket.listen(5)
        while True:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """Lida com a conexão de um cliente (outro nó).""" 
        while True:
            try:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                message = json.loads(data)
                if message['type'] == 'new_block':
                    self.handle_new_block(message['block'])
            except:
                break
        client_socket.close()

    def handle_new_block(self, block_data):
        """Processa um novo bloco recebido de outro nó.""" 
        block = Block(**block_data)
        self.blockchain.add_block(block)
        self.update_balance(block.miner)

    def start_mining_p2p(self):
        """Inicia a mineração em modo P2P.""" 
        if not self.miner_address:
            messagebox.showerror("Erro", "Nenhum endereço de minerador definido. Por favor, defina um.")
            return

        private_key = self.blockchain.key_vault.retrieve_key(self.miner_address)
        if private_key is None:
            messagebox.showerror("Erro", "Chave privada correspondente ao endereço do minerador não encontrada.")
            return

        self.is_mining = True
        self.mining_status_label.config(text="Status: Mineração iniciada...")
        mining_thread = threading.Thread(target=self.mine)  # Inicia a mineração em uma thread separada
        mining_thread.start()

    def stop_mining(self):
        """Interrompe o processo de mineração.""" 
        self.is_mining = False
        self.mining_status_label.config(text="Status: Mineração parada.")

    def mine(self):
        """Função de mineração que cria blocos continuamente.""" 
        while self.is_mining:
            last_block = self.blockchain.blocks[-1] if self.blockchain.blocks else self.blockchain.create_genesis_block()
            index = last_block.index + 1
            previous_hash = last_block.hash
            timestamp = time.time()
            data = f"Bloco minerado por {self.miner_address}"
            nonce = 0
            hash_value = self.blockchain.calculate_hash(index, previous_hash, timestamp, data, nonce)

            # Aumentar a dificuldade de mineração exigindo um hash que começa com mais zeros
            while hash_value[:6] != "000000":  # Exemplo: dificuldade de 6 zeros
                nonce += 1
                hash_value = self.blockchain.calculate_hash(index, previous_hash, timestamp, data, nonce)

            # Adiciona a recompensa ao minerador
            self.blockchain.miner_saldos[self.miner_address] = self.blockchain.miner_saldos.get(self.miner_address, 0) + self.blockchain.get_reward()

            new_block = Block(index, previous_hash, timestamp, data, nonce, hash_value, self.miner_address)  # Adiciona miner

            # Assina o bloco antes de enviar
            private_key = self.blockchain.key_vault.retrieve_key(self.miner_address)
            signature = self.blockchain.sign_message(private_key, hash_value)

            # Enviar o bloco para a rede P2P
            self.send_block_to_peers(new_block)

            # Adiciona o bloco à blockchain local
            self.blockchain.add_block(new_block)
            self.mining_status_label.config(text=f"Status: Bloco {index} minerado.")

    def send_block_to_peers(self, new_block):
        """Envia o novo bloco para os nós conectados na rede P2P.""" 
        block_data = new_block.__dict__
        message = json.dumps({"type": "new_block", "block": block_data})
        # Envia o bloco para todos os peers (apenas um exemplo básico, a implementação deve ser expandida)
        for peer in self.get_peers():
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect(peer)
                client_socket.send(message.encode())
                client_socket.close()
            except Exception as e:
                print(f"Erro ao enviar bloco para {peer}: {e}")

    def get_peers(self):
        """Retorna uma lista de peers conectados (apenas para fins de exemplo)."""
        # Aqui você pode implementar a lógica para gerenciar e retornar a lista de peers
        return []

    def view_blockchain(self):
        """Exibe a blockchain em uma caixa de texto rolável.""" 
        blockchain_info = self.blockchain.get_chain_info()
        text_box = scrolledtext.ScrolledText(self.window, width=70, height=20)
        text_box.insert(tk.INSERT, blockchain_info)
        text_box.pack(pady=5)
        text_box.config(state=tk.DISABLED)

    def create_wallet(self):
        """Cria uma nova carteira (chave pública e privada).""" 
        private_key = ecdsa.SigningKey.generate()  # Gera a chave privada
        public_key = private_key.get_verifying_key()  # Obtém a chave pública

        # Armazena as chaves como strings hexadecimais
        self.private_key_hex = private_key.to_string().hex()
        self.public_key_hex = public_key.to_string().hex()

        # Armazena as chaves no key vault
        self.blockchain.key_vault.store_key(self.public_key_hex, self.private_key_hex)
        
        # Copia as chaves para a área de transferência
        pyperclip.copy(f"Chave pública: {self.public_key_hex}\nChave privada: {self.private_key_hex}") 

        # Exibe as chaves em uma mensagem
        messagebox.showinfo("Nova Carteira", f"Chave pública e privada foram copiadas:\n\nChave pública:\n{self.public_key_hex}\n\nChave privada:\n{self.private_key_hex}")

        # Imprime as chaves no console
        print(f"Chave pública: {self.public_key_hex}")
        print(f"Chave privada: {self.private_key_hex}")
    
    def verify_signature(self, message, signature, public_key_hex):
        """Verifica uma assinatura usando a chave pública."""
        public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex))
        return public_key.verify(signature, message)

    def view_balance(self):
        """Exibe o saldo do minerador.""" 
        if self.miner_address:
            balance = self.blockchain.miner_saldos.get(self.miner_address, 0)
            messagebox.showinfo("Saldo", f"O saldo do minerador {self.miner_address} é: {balance} moedas.")
        else:
            messagebox.showerror("Erro", "Nenhum endereço de minerador definido.")

    def run(self):
        """Inicia a interface gráfica do aplicativo.""" 
        self.window.mainloop()

if __name__ == "__main__":
    app = BlockchainApp()
    app.run()
