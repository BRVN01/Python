$ cat socketserver.py
import socket
import ssl

# define o endereço IP do servidor (sem nada vai escutar em todos os endereços do servidor) e a porta
HOST = ''
PORT = 12345

# cria um socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# cria o contexto SSL
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='server.crt', keyfile='server.key')

# faz a ligação do socket com a porta
sock.bind((HOST, PORT))

# inicia o servidor
sock.listen(1)
print('Aguardando conexão...')

# espera a conexão do cliente
conn, addr = sock.accept()

# inicia o handshake SSL
conn_ssl = context.wrap_socket(conn, server_side=True)

# recebe a mensagem do cliente e decodifica
data = conn_ssl.recv(1024)
msg = data.decode()

# imprime a mensagem recebida
print('Mensagem recebida:', msg)

# fecha a conexão
conn_ssl.close()
