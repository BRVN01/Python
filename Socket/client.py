import socket
import ssl

# Configurações do servidor:
SERVER_ADDRESS = ('192.168.121.147', 12345)

# Cria um contexto SSL/TLS com a verificação do certificado desativada (aceita qualquer certificado):
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Cria um socket SSL/TLS com a verificação do certificado desativada:
sock = context.wrap_socket(socket.socket(socket.AF_INET), server_side=False)

# Conecta ao servidor
sock.connect(SERVER_ADDRESS)

# Envia uma mensagem ao servidor
message = 'Olá, servidor!'
sock.send(message.encode())

# Recebe a resposta do servidor
response = sock.recv(1024)
print(f'Resposta do servidor: {response.decode()}')

# Fecha a conexão com o servidor
sock.close()
