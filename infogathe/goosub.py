#!/bin/python

import sys
import httplib
import re
import urlparse
import time
import socket


CONFIG = {
        "google": "www.google.com",
        "port": 443,
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
    print "Uso:\n\t%s <DOMINIO BASE>" % sys.argv[0]
    print "Ej:\n\t%s example.com" % sys.argv[0]
    exit(1)


def buscar(dork="site:example.com", start=0):
    uri = "/search?q=%s&start=%s&filter=0" % (dork, start)

    time.sleep(CONFIG["delay"])
    conn = httplib.HTTPSConnection(CONFIG["google"], CONFIG["port"])
    conn.connect()
    conn.putrequest("GET", uri)
    conn.putheader("User-Agent", CONFIG["agent"])
    conn.putheader("Accept", "*/*")
    conn.endheaders()

    resp = conn.getresponse()
    html = resp.read()
    conn.close()

    patron = re.compile('<h3 class="r"><a href="([^"]*)"')
    urls = patron.findall(html)

    return urls


def gendork(base="example.com", dominios=[]):
    dork = "site:%s" % base
    for dominio in dominios:
        dork += "+-site:%s" % dominio
    return dork


def main():
    if len(sys.argv) != 2:
        uso()

    dominios = []
    base = sys.argv[1]

    ok = True
    while ok:
        dork = gendork(base, dominios)
        mensaje("[*] Dork: %s" % dork, 3, INFO)

        ok = False
        for start in range(0, CONFIG["paginas"]):
            mensaje("[*] Buscando pag. #%d" % (start + 1), 3, INFO)
            urls = buscar(dork, 0 + start * 10)

            if len(urls) == 0:
                mensaje("[-] No se obtubieron resultados.", 2, ERRO)
                break

            for url in urls:
                parseado = urlparse.urlparse(url)
                dominio = parseado.hostname
                if dominio is not None and dominio not in dominios and dominio != base:
                    dominios.append(dominio)
                    mensaje("[+] %s" % dominio, 1, NORM)
                    ok = True
    mensaje("[+] No encuentro mas, esto se acabo.", 1, NORM)

    dominios.sort()
    mensaje("[+] Se encontraron %d subdominios" % len(dominios), 1, NORM)
    mensaje("[+] Resultados: \n", 1, NORM)
    for dominio in dominios:
        try:
            _, _, ips = socket.gethostbyname_ex(dominio)
            for ip in ips:
                mensaje("%s\t%s" % (dominio, ip), 0, NORM)
        except:
            mensaje("%s\t-" % (dominio), 0, ERRO)
    return 0


if __name__ == "__main__":
    main()
