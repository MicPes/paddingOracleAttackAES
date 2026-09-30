## Implementazione di un Padding Oracle Attack su AES-CBC, con AES-128, in Python

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# --- SERVER (ORACOLO) --- 
class PaddingOracle:
    def __init__(self, key):
        # Chiave Segreta a 128 bit
        self.key = key 
    def padding_control(self, iv, ciphertext):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        try:
            paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()
            # Controllo del padding PKCS#7
            unpadder = padding.PKCS7(128).unpadder()
            unpadder.update(paddedPlaintext)
            unpadder.finalize()
            # Padding Valido
            return True 
        except:
            # Padding Non Valido
            return False 

# --- ATTACCANTE ---
def attack(ciphertext, iv, oracle):
    # Valore Intermedio (I)
    intermediateValue = [0] * 16 
    # Testo in Chiaro (P)
    decryptedBlock = [0] * 16 
    # Da byte 16 a byte 1 (15-0)
    for byteIndex in range(15, -1, -1): 
        targetPadding = 16 - byteIndex
        print(f"\n  [>] Ricerca byte {byteIndex} - Forzando padding di {hex(targetPadding)}")
        # IV modificabile
        testIntermediateValue = bytearray(iv)  
        # Preparazione dei byte a dx
        for i in range(byteIndex + 1, 16): 
            testIntermediateValue[i] = intermediateValue[i] ^ targetPadding 
        found = False
        for val in range(256):
            testIntermediateValue[byteIndex] = val
            if oracle.padding_control(bytes(testIntermediateValue), ciphertext):   
                # Calcolo del Valore Intermedio Ij
                intermediateValue[byteIndex] = val ^ targetPadding 
                # Calcolo del testo in chiaro Pj
                decryptedBlock[byteIndex] = intermediateValue[byteIndex] ^ iv[byteIndex]
                # Se il carattere è stampabile (tra lo spazio e la tilde) lo mostra;
                # Altrimenti mostra il suo valore Hex (fa vedere il padding!)
                if 32 <= decryptedBlock[byteIndex] <= 126:
                    char = f"'{chr(decryptedBlock[byteIndex])}'"
                else:
                    char = f"Padding ({hex(decryptedBlock[byteIndex])})"
                print(f"    [OK] Valore forzato in C'j-1[{byteIndex}]: {hex(val)}")
                print(f"    ['] Ij[{byteIndex}] = {hex(val)} ^ {hex(targetPadding)} = {hex(intermediateValue[byteIndex])}")
                print(f"    ['] Pj[{byteIndex}] = {hex(intermediateValue[byteIndex])} ^ {hex(iv[byteIndex])} = {char}")   
                found = True
                break
        if not found:
            return None
    return bytes(decryptedBlock)

# --- MAIN ---
if __name__ == "__main__":
    user_input = input("\n[?] Inserisci il messaggio: ")
    msg = user_input.encode()
    # --- PREPARAZIONE ---
    key = os.urandom(16)
    iv = os.urandom(16) 
    targetOracle = PaddingOracle(key)
    padder = padding.PKCS7(128).padder()
    paddedMsg = padder.update(msg) + padder.finalize()
    # --- CIFRATURA ---
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedMsg) + encryptor.finalize()
    print(f"Ciphertext: {ciphertext.hex()}")
    # --- ATTACCO ---
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    finalDecryptedMessage = b""
    currentIv = iv
    print("\n----------- PADDING ORACLE ATTACK -----------")
    for i in range(len(blocks)):
        print(f"\n[*] Attacco al Blocco {i+1} di {len(blocks)}")
        res = attack(blocks[i], currentIv, targetOracle)     
        if res:
            finalDecryptedMessage += res
            # Il blocco attuale diventa l'IV per il prossimo blocco
            currentIv = blocks[i]
        else:
            print("Errore nell'attacco.")
            break
    # Pulizia finale del padding
    unpadder = padding.PKCS7(128).unpadder()
    try:
        clean_msg = unpadder.update(finalDecryptedMessage) + unpadder.finalize()
        print(f"\n[+] Messaggio finale recuperato: {clean_msg.decode()}")
    except:
        print(f"\n[+] Messaggio recuperato (grezzo): {finalDecryptedMessage}")