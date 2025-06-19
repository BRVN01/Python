import argparse
import ssl
from os.path import isfile
import subprocess
import socket
import threading

class PortChanger:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--cert", required=False, help="Certificado")
        parser.add_argument("--key", required=False, help="Chave privada do certificado")
        parser.add_argument("--generate_cert", action="store_true", required=False, help="O sistema vai gerar o certificado e a chave privada.")
        parser.add_argument("--port", required=False, help="Porta que o socket vai escutar (se não definido o padrão será '2222')..")
        parser.add_argument("--ip", required=False, help="IP que o socket vai usar para abrir uma porta (se não definido o padrão será '0.0.0.0').")

        args = parser.parse_args()

        self.validate_arguments(parser, args)

    def validate_arguments(self, parser, args):

        if not any(vars(args).values()):
            parser.print_help()
            parser.exit(2, "\n\nAlgum argumento deve ser fornecido.\n")

        if args.ip:
            self.ip = args.ip
        else:
            self.ip = "0.0.0.0"

        if args.port:
            self.port = int(args.port)
        else:
            self.port = 2222

        if args.cert and args.key:
            if isfile(args.cert) and isfile(args.key):
                self.certfile = args.cert
                self.keyfile = args.key

                self.listen()
                parser.exit(0)
            else:
                print(f"O Certificado ou chave privada nao foi encontrado.")
                parser.exit(3)

        elif args.generate_cert:
            print("\nGerando certificado...\n")
            self.generate_cert()
            self.listen()
            parser.exit(0)

        else:
            print(f"O Certificado ou chave privada deve ser fornecido.")
            parser.exit(4)


    def generate_cert(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta, timezone

        # Gerar chave privada RSA
        chave = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Gerar um certificado autoassinado
        nome = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sao Paulo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sao Paulo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PortChanger"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        certificado = (
            x509.CertificateBuilder()
            .subject_name(nome)
            .issuer_name(nome)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            )
            .sign(chave, hashes.SHA256())
        )

        # Salvar a chave privada em um arquivo
        with open("key.pem", "wb") as f:
            f.write(chave.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Salvar o certificado em um arquivo
        with open("cert.pem", "wb") as f:
            f.write(certificado.public_bytes(serialization.Encoding.PEM))

        cmd = subprocess.run(["pwd"], check=True, stdout=subprocess.PIPE, text=True)
        path_files = cmd.stdout.splitlines()[0]

        self.certfile = path_files + '/' + "cert.pem"
        self.keyfile = path_files + '/' + "key.pem"

    def listen(self):
        print(f"\nOuvindo na interface x, na porta y...\n")

        # Cria um contexto SSL/TLS com a verificação do certificado desativada (aceita qualquer certificado):
        contexto = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        contexto.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.bind((self.ip, self.port))
        servidor.listen(5)

        while True:
            conexao, endereco = servidor.accept()
            conexao_tls = contexto.wrap_socket(conexao, server_side=True)
            thread = threading.Thread(target=self.handle_client, args=(conexao_tls, endereco))
            thread.start()

    def handle_client(self, conexao_tls, endereco):

        # Depois de 5 segundos que um cliente se conectou e nao enviou nada, ele sera desconectado:
        conexao_tls.settimeout(5.0)
        ip_cliente = endereco[0]
        
        try:
            while True:
                dados = conexao_tls.recv(1024)
                #ip_cliente = endereco[0]
                if not dados:
                    break
                msg = dados.decode().strip()
                self.handle_msg(msg, conexao_tls, ip_cliente)

        except Exception as e:
            print(f"{e}")

        finally:
            conexao_tls.shutdown(socket.SHUT_RDWR)
            conexao_tls.close()

    def handle_msg(self, msg, conexao_tls, ip_cliente):
        if msg == 'quit':
            self.quit(conexao_tls, ip_cliente)
        else:
            print(ip_cliente, msg)

    def quit(self, conexao_tls, ip_cliente):
        conexao_tls.sendall(b"\n\nEncerrando conexao\n\n")
        raise ConnectionAbortedError(f"Cliente {ip_cliente} pediu encerramento")

if __name__ == "__main__":
    init_class = PortChanger()
