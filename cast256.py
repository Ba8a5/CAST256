from functions_cast256 import * 
from utils import *
from key_generator import * 


def encrypt_block(message, key):
    """
    Cette fonction effectue le chiffrement d'un bloc de 128bits en exécutant les rounds successifs du cast-256
    :param message: le bloc à chiffrer (128bits)
    :param key: la clé de chiffrement (256bits)
    :return: le cryptogramme (128bits)
    """
    kr, km = key_generator(key)
    for i in range(6):
        message = forward_quad_round(message, kr[i], km[i])
    for j in range(6, 12):
        message = reverse_quad_round(message, kr[j], km[j])
    return message
   

def decrypt_block(cipher, key):
    """
    Cette fonction effectue le déchiffrement d'un bloc de 128bits en exécutant les rounds successifs du cast-256
    :param message: le bloc à déchiffrer (128bits)
    :param key: la clé de chiffrement (256bits)
    :return: le message (128bits)
    """
    kr, km = key_generator(key)   
    for i in range(11, 5, -1):  
        cipher = forward_quad_round(cipher, kr[i], km[i])
    for j in range(5,-1, -1):  
        cipher = reverse_quad_round(cipher, kr[j], km[j])
    return cipher
