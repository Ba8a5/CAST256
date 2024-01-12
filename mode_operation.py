import secrets

from cast256 import *


def rdm_iv_generator():
    """
    Cette fonction doit pouvoir générer un nombre aléatoire de 128bits
    :return: un entier représenté sur 128 bits généré de manière aléatoire.
    """
    return secrets.randbits(128)


def encrypt_ecb(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération ECB.
    :param blocks: Liste de blocs (128bits) à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés.
    """
    encrypted_ecb = []
    
    for block in blocks:
        encrypted_ecb.append(encrypt_block(block, key))
    return encrypted_ecb


def decrypt_ecb(blocks, key):
    """
    Cette fonction dé-chiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_ecb = []
    
    for block in blocks:
        decrypted_ecb.append(decrypt_block(block, key) % 256)
    return decrypted_ecb


def encrypt_cbc(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    encrypted_cbc = []
    
    iv = rdm_iv_generator()
    prev_block = iv
    for block in blocks:
        pre_encrypted_block = block ^ prev_block
        encrypted_block = encrypt_block(pre_encrypted_block, key)
        prev_block = encrypted_block
        encrypted_cbc.append(encrypted_block)
    encrypted_cbc.insert(0, iv)
    return encrypted_cbc


def decrypt_cbc(blocks, key):
    """
    Cette fonction dé-chiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_cbc = []
    
    prev_block = blocks[0]
    for block in blocks[1:]:
        pre_decrypt_block = decrypt_block(block, key)
        decrypted_block = pre_decrypt_block ^ prev_block
        prev_block = block
        decrypted_cbc.append(decrypted_block)
    return decrypted_cbc


def decrypt(blocks, key, operation_mode="ECB"):
    """
    Cette fonction déchiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération CBC ou ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: La clé de chiffrement 256 bits.
    :param operation_mode: String spécifiant le mode d'opération ("ECB" ou "CBC").
    :return: La liste de blocs déchiffrés.
    """
    decrypted_blocks = []

    if operation_mode == "ECB":
        for block in blocks:
            decrypted_blocks.append(decrypt_block(block, key) % 256)
    elif operation_mode == "CBC":
        decrypted_blocks = decrypt_cbc(blocks, key)
    else:
        raise ValueError("Mode d'opération non pris en charge")

    return decrypted_blocks


def encrypt(blocks, key, operation_mode="ECB"):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits.
    :param blocks: Liste de blocs à chiffrer.
    :param key: La clé de chiffrement 256 bits.
    :param operation_mode: String spécifiant le mode d'opération ("ECB" ou "CBC").
    :return: La liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    encrypted_blocks = []

    if operation_mode == "ECB":
        for block in blocks:
            encrypted_blocks.append(encrypt_block(block, key))
    elif operation_mode == "CBC":
        encrypted_blocks = encrypt_cbc(blocks, key)
    else:
        raise ValueError("Mode d'opération non pris en charge")

    return encrypted_blocks
