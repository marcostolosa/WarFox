from OpenSSL import crypto, SSL
import os

def generate_certs(
  

    KEY_FILE = "hightower.key",
    CERT_FILE = "hightower.crt",

    serialNumber = 0,
    validityStartInSeconds = 0,
    validityEndInSeconds=10*365*24*60*60):

    if os.path.exists(CERT_FILE) or os.path.exists(KEY_FILE):
        print("\n[!WARNING!] Generated certs already exist on disk")
        print("\t[+] CERT_FILE: " + os.path.abspath(CERT_FILE))
        print("\t[+] KEY_FILE: "  + os.path.abspath(KEY_FILE))
        
    else:

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C  = "  "
        cert.get_subject().ST = " "
        cert.get_subject().L  = " "
        cert.get_subject().O  = " "
        cert.get_subject().OU = " "
        cert.get_subject().CN = " "
        cert.get_subject().emailAddress = " "
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # write certs to a sslcert folder
        with open(CERT_FILE, "wt") as output_certificate:
            output_certificate.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(KEY_FILE, "wt") as output_private_key:
            output_private_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

        print("[+] New certificate and key pair has been generated\n");