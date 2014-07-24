#!/bin/python

import httplib
import sys
import time
import re
import socket
import urlparse

CONFIG = {
        "bing": "www.bing.com",
        "port": 80,
        "paginas": 10,
        "delay": 3,
        "agent": "Mozilla/5.0 (X11; Linux x86_64; rv:26.0) Gecko/20100101 Firefox/26.0",
        "verbose": 3
    }
NORM = "\033[1;92m"
INFO = "\033[1;93m"
ERRO = "\033[1;91m"
ENDM = "\033[0m"


def mensaje(mensaje="Hola Mundo!", verb=1, color=NORM):
    if verb <= CONFIG["verbose"]:
        print color + mensaje + ENDM


def uso():
    print "Uso:\n\t%s <IP>" % sys.argv[0]
    print "Ej:\n\t%s 93.184.216.119" % sys.argv[0]
    exit(1)


def buscar(dork="site:example.com", first=1):
    uri = "/search?q=%s&first=%s" % (dork, first)

    time.sleep(CONFIG["delay"])
    conn = httplib.HTTPConnection(CONFIG["bing"], CONFIG["port"])
    conn.connect()
    conn.putrequest("GET", uri)
    conn.putheader("User-Agent", CONFIG["agent"])
    conn.putheader("Accept", "*/*")
    conn.endheaders()

    resp = conn.getresponse()
    html = resp.read()
    conn.close()

    #patron = re.compile('<div class="sb_tlst"><h3><a href="([^"]*)"')
    patron = re.compile('<h2><a href="([^"]*)" h="[^"]*">[^<]*</a></h2>')
    urls = patron.findall(html)

    return urls


def main():
    if len(sys.argv) != 2:
        uso()

    ip = sys.argv[1]
    dominios = []
    validos = []
    invalidos = []
    inexistentes = []

    dork = "ip:%s" % ip
    pagina = 1

    while True:
        urls = buscar(dork, pagina)

        for url in urls:
            dominio = urlparse.urlparse(url).hostname
            if dominio is not None and dominio not in dominios:
                dominios.append(dominio)

                try:
                    _, _, ips = socket.gethostbyname_ex(dominio)
                    if ip in ips:
                        validos.append(dominio)
                        mensaje("[+] %s: %s" % (dominio, ", ".join(ips)), 1, NORM)
                    else:
                        invalidos.append(dominio)
                        mensaje("[*] %s: %s" % (dominio, ", ".join(ips)), 1, INFO)
                except:
                    inexistentes.append(dominio)
                    mensaje("[-] %s no se pudo resolver" % dominio, 1, ERRO)

        if len(urls) < 10:
            break
        else:
            pagina += 10
    mensaje("[+] Terminado", 1, NORM)

    mensaje("\nTOTAL DOMINIOS: %d" % len(dominios), 0, NORM)

    if len(validos) > 0:
        mensaje("\n# DOMINIOS VALIDOS: %d" % len(validos), 0, NORM)
        validos.sort()
        for dominio in validos:
            mensaje(dominio, 0, NORM)

    if len(invalidos) > 0:
        mensaje("\n# DOMINIOS INVALIDOS: %d" % len(invalidos), 0, INFO)
        invalidos.sort()
        for dominio in invalidos:
            mensaje(dominio, 0, INFO)

    if len(inexistentes) > 0:
        mensaje("\n# DOMINIOS INEXISTENTES: %d" % len(inexistentes), 0, ERRO)
        inexistentes.sort()
        for dominio in inexistentes:
            mensaje(dominio, 0, ERRO)

    return 0


if __name__ == "__main__":
    main()
