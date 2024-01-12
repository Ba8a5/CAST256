import math

from utils import * 
from functions_cast256 import *


def forward_octave(abcdefgh, tr, tm):
    """
      Cette fonction correspond à la forward_octave du cast-256. Elle décompose le bloc d'entrée 256bits en
      blocs de 32bits. Ces blocs sont transformés par l'utilisation des fonctions f1, f2 et f3 du cast-256 en utilisant
      les clés de rotation et de masque. Les blocs obtenus sont recomposés en un bloc de 256bits.
      !!! ATTENTION A L'ORDRE DES OPERATIONS INDIQUE DANS LA DOCUMENTATION !!!
      :param abcdefgh: le bloc à traité (256bits)
      :param tr: tableau de 8 clés de rotation (8bits)
      :param tm: tableau de 8 clés de masque (32bits)
      :return: le résultat des opérations (256bits)
      """
    A, B, C, D, E, F, G, H = extract_32bit_bloc_from_256(abcdefgh)
    G = G ^ function1(H, tr[0], tm[0])
    F = F ^ function2(G, tr[1], tm[1])
    E = E ^ function3(F, tr[2], tm[2])
    D = D ^ function1(E, tr[3], tm[3])
    C = C ^ function2(D, tr[4], tm[4])
    B = B ^ function3(C, tr[5], tm[5])
    A = A ^ function1(B, tr[6], tm[6])
    H = H ^ function2(A, tr[7], tm[7])
    return build_256_bit_bloc_from_32_bit_blocs(A, B, C, D, E, F, G, H)


def initialization():
    """
    Cette fonction crée les clés de rotation tr et de masque tm utiles à la génération des clés du cast-256.
    :return: deux tableaux à deux dimensions 8x24 (24 lignes et 8 colonnes) contenant respectivement
    les clés de rotation tr et de masque tm.
    """

    cm = 2 ** 30 * math.sqrt(2)
    mm = 2 ** 30 * math.sqrt(3)
    cr = 19
    mr = 17 
    tm = [[0] * 8 for _ in range(24)]
    tr = [[0] * 8 for _ in range(24)]
    for i in range(24):
        for j in range(8): 
            tm[i][j] = cm 
            cm = sum_mod_232(cm, mm)
            tr[i][j] = cr
            cr = sum_mod_232(cr, mr)
    return tm, tr 


def key_generator(key):
    """
    Cette fonction génère les clés de rotation kr et de masque km pour le chiffrement cast-256 à partir de la clé 256bits
    de chiffrement et des clés de rotation tr et de masque tm.
    :param key: la clé de chiffrement (256bits)
    :return: deux tableaux à deux dimensions 12x4 (12 lignes et 4 colonnes) contenant respectivement
    les clés de rotation kr et de masque km.
    """
    tm, tr = initialization()
    kr = []
    km = []
    for i in range(0, 24, 2):     
        key = forward_octave(key, tr[i], tm[i])
        key = forward_octave(key, tr[i+1], tm[i+1])
        a, b, c, d, e, f, g, h = extract_32bit_bloc_from_256(key)
        kr.append([lsb5(a), lsb5(c), lsb5(e), lsb5(g)])
        km.append([h, f, d, b]) 
    return kr, km 

