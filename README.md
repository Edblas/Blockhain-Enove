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
import os

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
        self.load_data()  # Carrega dados persistentes
        if not self.blocks:
            self.create_genesis_block()

    def create_genesis_block(self):
        """Cria o bloco gênese e o adiciona à blockchain."""
        genesis_block = Block(0, "0", time.time(), "Bloco Gênese", 0, "0", "Genesis")
        self.blocks.append(genesis_block)
        self.save_data()  # Salva os dados após criar o bloco gênese

    def calculate_hash(self, index, previous_hash, timestamp, data, nonce):
        """Calcula o hash de um bloco."""
        value = f"{index}{previous_hash}{timestamp}{data}{nonce}".encode()
        return hashlib.sha256(value).hexdigest()

    def add_block(self, new_block):
        """Adiciona um bloco à blockchain após validação."""
        self.blocks.append(new_block)
        self.update_balance(new_block.miner)  # Atualiza o saldo do minerador
        self.save_data()  # Salva os dados após adicionar um novo bloco

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

    def save_data(self):
        """Salva a blockchain e o key vault em um arquivo JSON."""
        data = {
            'blocks': [block.__dict__ for block in self.blocks],
            'keys': self.key_vault.keys,
            'miner_saldos': self.miner_saldos
        }
        with open('blockchain_data.json', 'w') as f:
            json.dump(data, f)

    def load_data(self):
        """Carrega dados persistentes da blockchain a partir de um arquivo."""
        try:
            with open('blockchain_data.json', 'r') as f:
                data = json.load(f)
                self.blocks = [Block(**block) for block in data.get('blocks', [])]
                self.key_vault.keys = data.get('keys', {})
                self.miner_saldos = data.get('miner_saldos', {})
        except FileNotFoundError:
            self.blocks = []  # Inicializa uma blockchain vazia
        except json.JSONDecodeError:
            self.blocks = []  # Se o JSON estiver malformado

    def update_balance(self, miner_address):
        """Atualiza o saldo do minerador com base nas recompensas recebidas."""
        if miner_address not in self.miner_saldos:
            self.miner_saldos[miner_address] = 0
        self.miner_saldos[miner_address] += self.get_reward()

class BlockchainApp:
    """Classe que representa a interface do aplicativo de blockchain."""
    def __init__(self):
        self.blockchain = Blockchain()
        self.miner_address = ""
        self.is_mining = False
        self.window = tk.Tk()
        self.window.title("Enove Blockchain")
        self.window.geometry("600x600")

        # Labels e botões da interface
        tk.Label(self.window, text="Endereço do Minerador:").pack(pady=5)
        self.miner_address_label = tk.Label(self.window, text=self.miner_address)
        self.miner_address_label.pack(pady=5)

        tk.Button(self.window, text="Definir Endereço do Minerador", command=self.set_miner_address).pack(pady=5)
        tk.Button(self.window, text="Iniciar Mineração P2P", command=self.start_mining_p2p).pack(pady=5)
        tk.Button(self.window, text="Parar Mineração", command=self.stop_mining).pack(pady=5)
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

    def mine(self):
        """Função de mineração que cria novos blocos.""" 
        while self.is_mining:
            last_block = self.blockchain.blocks[-1]
            index = last_block.index + 1
            timestamp = time.time()
            data = f"Minerando em {self.miner_address}"
            nonce = 0
            hash_result = self.blockchain.calculate_hash(index, last_block.hash, timestamp, data, nonce)
            while not hash_result.startswith("0000"):  # Dificuldade do hash
                nonce += 1
                hash_result = self.blockchain.calculate_hash(index, last_block.hash, timestamp, data, nonce)

            new_block = Block(index, last_block.hash, timestamp, data, nonce, hash_result, self.miner_address)
            self.blockchain.add_block(new_block)  # Adiciona o novo bloco à blockchain
            self.broadcast_new_block(new_block)  # Envia o novo bloco para a rede P2P
            time.sleep(10)  # Simula o tempo entre os blocos (pode ser ajustado)

    def broadcast_new_block(self, new_block):
        """Envia um novo bloco para todos os nós na rede P2P.""" 
        block_data = json.dumps({'type': 'new_block', 'block': new_block.__dict__}).encode()
        # Aqui você precisará implementar a lógica para enviar o bloco para todos os nós conectados

    def stop_mining(self):
        """Para o processo de mineração.""" 
        self.is_mining = False
        self.mining_status_label.config(text="Status: Mineração parada.")

    def create_wallet(self):
        """Cria uma nova carteira e exibe a chave pública e privada.""" 
        private_key = os.urandom(32).hex()
        public_key = hashlib.sha256(private_key.encode()).hexdigest()  # Simples chave pública
        self.blockchain.key_vault.store_key(public_key, private_key)  # Armazena as chaves
        messagebox.showinfo("Carteira Criada", f"Chave Pública: {public_key}\nChave Privada: {private_key}")
        pyperclip.copy(f"Chave Pública: {public_key}\nChave Privada: {private_key}")

    def view_balance(self):
        """Exibe o saldo do minerador.""" 
        if not self.miner_address:
            messagebox.showerror("Erro", "Nenhum endereço de minerador definido.")
            return

        balance = self.blockchain.miner_saldos.get(self.miner_address, 0)
        messagebox.showinfo("Saldo", f"Saldo do Minerador: {balance} moedas")

    def view_blockchain(self):
        """Exibe a blockchain em uma janela de texto rolável.""" 
        blockchain_info = self.blockchain.get_chain_info()
        viewer = tk.Toplevel(self.window)
        viewer.title("Blockchain")
        text_area = scrolledtext.ScrolledText(viewer, width=80, height=30)
        text_area.insert(tk.INSERT, blockchain_info)
        text_area.config(state=tk.DISABLED)  # Desabilita edição
        text_area.pack()
        
    def run(self):
        """Executa a interface do aplicativo."""
        self.window.mainloop()

if __name__ == "__main__":
    app = BlockchainApp()
    app.run()

