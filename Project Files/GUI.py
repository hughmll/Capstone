import PySimpleGUI as sg
from File_parser_tool import file_parser
from PBKDF import key_derivation
from Crypto.Protocol.KDF import PBKDF2 #required unless importing Encrypt_Decrypt.py
from Crypto.Hash import SHA3_512 #required unless importing Encrypt_Decrypt.py
from Crypto.Cipher import AES #required unless importing Encrypt_Decrypt.py
import os
import tempfile
### WCAG 2.1 success criteria:
#1.4.4 > dynamically resize text up to 200% of original without assistive software
#2.4.9 > purpose of each link/button identified from link/button text alone (FLASH27)
#2.2.3 > timing is not essential part of the event or activity
#2.2.6 > no requirement to warn users of timeouts as data should be preserved beyond 20 hours if application left running if not action taken
#1.4.3 > text contrast ratio of at least 4.5:1

sg.theme('SystemDefault')
layout = [[sg.Text('Click browse to find your configuration file', font=None, key='-BROWSE-'), sg.Push(), sg.InputText(readonly=True,), sg.FileBrowse('Browse', key='-FILE-', font=None)],
          [sg.Text('Enter password to decrypt file here'), sg.Push(), sg.InputText(key='-PASSWORD-', password_char='*')],
          [sg.Text('', text_color='Red', key='-ERROR-')],
          [sg.Text('', text_color='Green', key='-SUCCESS-')],
          [sg.Button('Decrypt')],
          [sg.Text('Server Address'), sg.Input(readonly=True, key='-SERVER-', size=(25,1)), sg.Push(), sg.Button('Connect', visible=False, key='-CONNECT-')],
          [sg.Text('DNS                '), sg.Input(readonly=True, key='-DNS-', size=(25,1)), sg.Push(), sg.Button('Disconnect', visible=False, key='-DISCONNECT-')],
          [sg.Button(visible=False, key='-INPUT-', bind_return_key=True)]]




window = sg.Window('Wireguard Client', layout)
var_dict = {}
decrypted_text = ""
tempdir = tempfile.gettempdir() #gets default temp directory relative to user
file_name = "\\wgtunnel.conf"
file_path = tempdir + file_name #sets name for temp .conf file that will be used for tunnel establishment
tunnel_name = 'wgtunnel' #used to identify tunnel interface when passing tunnel tear down command
large_text = False #boolean state is used as switch in combination with 'INPUT- event for whether text should be enlarged or not after hitting enter key

#the write_comf_file function is needed for the following reasons:
#> WG is invoked via cmd and requires .conf file as input to begin tunnel session
#> WG Windows specifically requires CR LF characters after each line with the exception of the last line to parse the .conf file correctly
# the function below writes the conf file to be used to establish the tunnel session with CR LF after each line (including the blank link separating
# client from peer (server). It pulls details from the var_dict dictionary storing the data parsed from the decrypted conf file
def write_conf_file():
    with open(f"{tempdir}{file_name}", "w", newline='\r\n') as conf_file:
        conf_file.write("[Interface]\n")
        conf_file.write("PrivateKey = " + var_dict['PrivateKey'] + "\n")
        conf_file.write("Address = " + var_dict['Address'] + "\n")
        conf_file.write("DNS = " + var_dict['DNS'] + "\n")
        conf_file.write("\n")
        conf_file.write("[Peer]\n")
        conf_file.write("PublicKey = " + var_dict['PublicKey'] + "\n")
        conf_file.write("AllowedIPs = " + var_dict['AllowedIPs'] + "\n")
        conf_file.write("Endpoint = " + var_dict['Endpoint'])



def decryption(password, file):
    global decrypted_text
    password = password.encode() #converts passed utf-8 byte string (decrypt function only works with byte strings)
    file = file #file for decryption
    key = key_derivation(password) #generates symmetric key instance to perform decryption
    try:
        with open(file,  "rb") as encrypted_data:
            nonce = encrypted_data.read(16) #reads first 16 bytes of encrypted file to grab nonce value for passing to key object generator
    except FileNotFoundError:
        print("You must select a file")
        return
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
        window['-SUCCESS-'].update('Password correct')
    except ValueError:
        print("Decryption failed. Either your password is incorrect or the file has been altered")
        return 1 #if decryption fails, returns this value as output of func

large_text = False
while True:
    event,values = window.read()
    print(large_text)
    if event == sg.WIN_CLOSED or event == 'Exit':
        if os.path.exists(file_path):
            os.remove(file_path)
            exit()
        else:
            exit()
    if event == 'Decrypt': #when decrypt button is pressed
        window['-ERROR-'].update('')
        #with open(values['-FILE-'], 'rb') as test_file:
        result = decryption(values['-PASSWORD-'], values['-FILE-'])
        if result == 1: #checks if 1 was returned by decryption func (meaning decryption failed)
            window['-ERROR-'].update('Password incorrect')
            continue    # If result is 1, returns to start of loop to allow for new 'Decrypt' event (user can try entering password again)
        try:
            file_parser(decrypted_text, var_dict)
        except AttributeError:
            continue
        window['-SERVER-'].update(var_dict['Endpoint'])
        window['-DNS-'].update(var_dict['DNS'])
        window['-CONNECT-'].update(visible=True)
        print(var_dict)
        print(var_dict["PrivateKey"])
        write_conf_file()
    if event == '-CONNECT-': #when connect button is pressed
        os.system('cmd /C "wireguard /installtunnelservice %s"' % file_path)
        #tunnel = True
        window['-CONNECT-'].update(visible=False) #makes connect button invisible once pressed
        window['-DISCONNECT-'].update(visible=True) #makes disconnect button visible
    if event == '-DISCONNECT-': #when disconnect button is pressed
        os.system('cmd /C "wireguard /uninstalltunnelservice %s"' % tunnel_name)
        #tunnel = False
        window['-CONNECT-'].update(visible=True) #the above but reversed
        window['-DISCONNECT-'].update(visible=False)
    if event == '-INPUT-' and large_text == False:
        window['-BROWSE-'].update(font='Any 20')
        large_text = True
    elif event == '-INPUT-' and large_text == True:
        window['-BROWSE-'].update(font='Any 10')
        large_text = False


window.close()