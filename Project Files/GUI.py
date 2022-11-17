import PySimpleGUI as sg
from File_parser_tool import file_parser
from PBKDF import key_derivation
from Crypto.Protocol.KDF import PBKDF2 #required unless importing Encrypt_Decrypt.py
from Crypto.Hash import SHA3_512 #required unless importing Encrypt_Decrypt.py
from Crypto.Cipher import AES #required unless importing Encrypt_Decrypt.py
import os
import tempfile

sg.theme('SystemDefault')
layout = [[sg.Text('Click browse to find your configuration file'), sg.InputText(readonly=True), sg.FileBrowse('Browse', key='-FILE-')],
          [sg.Text('Enter password to decrypt file here         '), sg.InputText(key='-PASSWORD-', password_char='*')],
          [sg.Text('', text_color='Red', key='-ERROR-')],
          [sg.Text('', text_color='Green', key='-SUCCESS-')],
          [sg.Button('Decrypt')],
          [sg.Text('Server Address'), sg.Input(readonly=True, key='-SERVER-', size=(25,1)), sg.Push(), sg.Button('Connect', visible=False, key='-CONNECT-')],
          [sg.Text('DNS                '), sg.Input(readonly=True, key='-DNS-',size=(25,1)), sg.Push(), sg.Button('Disconnect', visible=False, key='-DISCONNECT-')]]




window = sg.Window('Wireguard Client', layout)
var_dict = {}
decrypted_text = ""
tempdir = tempfile.gettempdir()
filename = '\\wgtunnel.conf'
name_only = 'wgtunnel'

def write_conf_file():
    with open(f"{tempdir}{filename}", "a") as conf_file:
        conf_file.write("[INTERFACE]\r\n")
        conf_file.write("PrivateKey = " + var_dict[PrivateKey] + "\r\n")
        conf_file.write("Address = " + var_dict[Address] + "\r\n")
        conf_file.write("DNS = " + var_dict[DNS] + "\r\n")
        conf_file.write("\r\n")
        conf_file.write("[PEER]\r\n")
        conf_file.write("PublicKey = " + var_dict[PublicKey] + "\r\n")
        conf_file.write("AllowedIPs = " + var_dict[AllowedIPs] + "\r\n")
        conf_file.write("Endpoint = " + var_dict[Endpoint])



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
    tunnel = False
    if tunnel == True:
        window['-CONNECT-'].update(visible=False)
        window['-DISCONNECT-'].update(visible=True)
    if event == sg.WIN_CLOSED or event == 'Exit':
        exit()
    if event == 'Decrypt':
        window['-ERROR-'].update('')
        #with open(values['-FILE-'], 'rb') as test_file:
        result = decryption(values['-PASSWORD-'], values['-FILE-'])
        if result == 1: #checks if 1 was returned by decryption func (meaning decryption failed)
            window['-ERROR-'].update('Password incorrect')
            continue    # If result is 1, returns to start of loop to allow for new 'Decrypt' event (user can try entering password again)
        else:
            window['-SUCCESS-'].update('Password correct')
        #data = test_file.read()
        file_parser(decrypted_text, var_dict)
        window['-SERVER-'].update(var_dict['Endpoint'])
        window['-DNS-'].update(var_dict['DNS'])
        window['-CONNECT-'].update(visible=True)
        print(var_dict)
        #with open(f"{tempdir}{filename}", "w") as conf_file:

    if event == '-CONNECT-':
        print('hello there')
        tunnel = True
        window['-CONNECT-'].update(visible=False)
        window['-DISCONNECT-'].update(visible=True)
    if event == '-DISCONNECT-':
        tunnel = False
        window['-CONNECT-'].update(visible=True)
        window['-DISCONNECT-'].update(visible=False)

window.close()