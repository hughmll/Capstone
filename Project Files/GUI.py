import PySimpleGUI as sg
from File_parser_tool import file_parser
from PBKDF import key_derivation
from Crypto.Protocol.KDF import PBKDF2 #required unless importing Encrypt_Decrypt.py
from Crypto.Hash import SHA3_512 #required unless importing Encrypt_Decrypt.py
from Crypto.Cipher import AES #required unless importing Encrypt_Decrypt.py


layout = [[sg.Text('Click browse to find your configuration file'), sg.InputText(readonly=True), sg.FileBrowse('Browse', key='-FILE-')],
          [sg.Text('Enter password to decrypt file here         '), sg.InputText(key='-PASSWORD-', password_char='*')],
          [sg.Text('', text_color='Red', key='-ERROR-')],
          [sg.Button('Decrypt')],
          [sg.Text('IP Address'), sg.Input(readonly=True, key='-ADDRESS-', size=(16,1))],
          [sg.Text('DNS         '), sg.Input(readonly=True, key='-DNS-',size=(16,1))]]



window = sg.Window('Wireguard Client', layout)
var_dict = {}
decrypted_text = ""

def decryption(password, file):
    global decrypted_text
    password = password.encode()
    file = file
    key = key_derivation(password)
    with open(file,  "rb") as encrypted_data:
        nonce = encrypted_data.read(16) #reads first 16 bytes of encrypted file to grab nonce value for passing to key object generator
    with open(file, "rb") as encrypted_data:
        encrypted_data.seek(16) #opens file again and moves  to 16 byte offset from beginning of file
        tag = encrypted_data.read(16) #reads only 16 bytes after 16 byte offset to get MAC tag for verification
    with open(file, "rb") as encrypted_data:
        encrypted_data.seek(32) #moves to 32 byte offset from beginning of file (to skip nonce and tag)
        cipher_text2 = encrypted_data.read() # reads rest of file after offset to get ciphertext only
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) # new encryption object instantiated for decryption
    #deciphered_text = cipher.decrypt_and_verify(cipher_text2) #ciphertext decrypted and tag verified
    try:
        decrypted_text = cipher.decrypt_and_verify(cipher_text2, tag) #ciphertext decrypted and tag verified
    except ValueError:
        print("Decryption failed. Either your password is incorrect or the file has been altered")
        return 1 #if decryption fails, returns this value as output of func


while True:
    event,values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        exit()
    elif event == 'Decrypt':
        window['-ERROR-'].update('')
        #with open(values['-FILE-'], 'rb') as test_file:
        result = decryption(values['-PASSWORD-'], values['-FILE-'])
        if result == 1: #checks if 1 was returned by decryption func (meaning decryption failed)
            window['-ERROR-'].update('Password incorrect')
            continue    # If result is 1, returns to start of loop to allow for new 'Decrypt' event (user can try entering password again)
        #data = test_file.read()
        file_parser(decrypted_text, var_dict)
        window['-ADDRESS-'].update(var_dict['Address'])
        window['-DNS-'].update(var_dict['DNS'])

window.close()