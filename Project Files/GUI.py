import PySimpleGUI as sg
from PBKDF import key_derivation
from Crypto.Protocol.KDF import PBKDF2 #required unless importing Encrypt_Decrypt.py
from Crypto.Hash import SHA3_512 #required unless importing Encrypt_Decrypt.py
from Crypto.Cipher import AES #required unless importing Encrypt_Decrypt.py
import os
import tempfile
from gtts import gTTS
import playsound
import time
### WCAG 2.1 success criteria:
#1.4.4 > dynamically resize text up to 200% of original without assistive software
#2.4.9 > purpose of each link/button identified from link/button text alone (FLASH27)
#2.2.3 > timing is not essential part of the event or activity
#2.2.6 > no requirement to warn users of timeouts as data should be preserved beyond 20 hours if application left running if not action taken
#1.4.3 > text contrast ratio of at least 4.5:1


sg.theme('SystemDefault')
layout = [[sg.Text('Click browse to find your configuration file', font=None, key='-BROWSE-'), sg.Push(), sg.InputText(readonly=True,), sg.FileBrowse('Browse', key='-FILE-')],
          [sg.Text('Enter password to decrypt file here          ', font=None, key='-PASS_PROMPT-'), sg.InputText(key='-PASSWORD-', password_char='*'), sg.Checkbox('Show Password', key='-CHECKBOX-', enable_events=True)],
          [sg.Text('Your password is incorrect or the file has been corrupted', text_color='Red', key='-ERROR-', visible=False)],
          [sg.Text('Password correct', text_color='Green', key='-SUCCESS-', visible=False)],
          [sg.Button('Decrypt', button_color=('Black','Orange'))],
          [sg.Text('Server Address: ', font=None, key='-S-'), sg.Text('', key='-SERVER-', background_color=None), sg.Push(), sg.Button('Connect', visible=False, key='-CONNECT-', button_color='green')],
          [sg.Text('DNS: ', font=None, key='-D-'), sg.Text('', key='-DNS-', background_color=None), sg.Push(), sg.Button('Disconnect', visible=False, key='-DISCONNECT-', button_color='red')],
          [sg.Button('How to use this application', key='-HOW-', button_color=('Black','LightBlue')), sg.Button(visible=False, key='-INPUT-', bind_return_key=True)]]


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

def new_window():
    layout = [[sg.Text('This is the help window')]]
    window = sg.Window('About', layout, modal=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Exit':
            break
    window.close()

def speak(speech):
    tts = gTTS(text=speech, lang='en')
    filename = "speech.mp3"
    tts.save(filename)
    playsound.playsound(filename)
    os.remove(filename)

def file_parser(x, y): #x is used as placeholder for passing in bytes read from file and y is for passing in empty dictionary
    data = x.decode().split("\n")
    var_dict = y
    #print(data)
    for item in data:
        if "[Interface]" in item:
            item.replace("[Interface]", "")
        elif item == "\r":
            item.replace("\r","")
        elif "[Peer]" in item:
            item.replace("[Peer]", "")
        elif "\r" in item:
            item = item.replace("\r", "")
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value
        else:
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value

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
        #window['-SUCCESS-'].update(visible=True)
    except ValueError:
        print("Decryption failed. Either your password is incorrect or the file has been altered")
        return 1 #if decryption fails, returns this value as output of func

large_text = False
#speak('The Wireguard VPN connection client is about to open')
#speak('On the next screen, click the light blue button at the bottom to learn how to use the client')

while True:
    event,values = window.read()
    window['-ERROR-'].update(visible=False)
    window['-SUCCESS-'].update(visible=False)
    if event == sg.WIN_CLOSED or event == 'Exit':
        if os.path.exists(file_path):
            os.remove(file_path)
            exit()
        else:
            exit()
    if event == '-HOW-':
        print('you clicked about')
        new_window()
    if event == 'Decrypt': #when decrypt button is pressed
        #with open(values['-FILE-'], 'rb') as test_file:
        result = decryption(values['-PASSWORD-'], values['-FILE-'])
        if result == 1: #checks if 1 was returned by decryption func (meaning decryption failed)
            window['-ERROR-'].update(visible=True)
            continue    # If result is 1, returns to start of loop to allow for new 'Decrypt' event (user can try entering password again)
        try:
            file_parser(decrypted_text, var_dict)
        except AttributeError:
            continue
        window['-SERVER-'].update(var_dict['Endpoint'], background_color='white')
        window['-DNS-'].update(var_dict['DNS'], background_color='white')
        window['-CONNECT-'].update(visible=True)
        window['-SUCCESS-'].update(visible=True)
        print(var_dict)
        print(var_dict["PrivateKey"])
        write_conf_file()
        #speak('You will now be able to connect using the green connect button on the bottom right')
    if event == '-CONNECT-': #when connect button is pressed
        #speak('Connection in progress. Once connected, you can disconnect using the red disconnect button')
        os.system('cmd /C "wireguard /installtunnelservice %s"' % file_path)
        window['-CONNECT-'].update(visible=False) #makes connect button invisible once pressed
        window['-DISCONNECT-'].update(visible=True) #makes disconnect button visible
    if event == '-DISCONNECT-': #when disconnect button is pressed
        os.system('cmd /C "wireguard /uninstalltunnelservice %s"' % tunnel_name)
        window['-CONNECT-'].update(visible=True) #the above but reversed
        window['-DISCONNECT-'].update(visible=False)
    if values['-CHECKBOX-'] == True: #this checks if show password checkbox is ticked and then sets password input field to show plaintext
        window['-PASSWORD-'].update(password_char='')
    if values['-CHECKBOX-'] == False: #this checks if show password checkbox is unticked and then sets password input field to show * only
        window['-PASSWORD-'].update(password_char='*')
    if event == '-INPUT-' and large_text == False: #This resizes text 200% larger than standard if Enter key is hit
        window['-BROWSE-'].update(font='Any 30')
        window['-ERROR-'].update(font='Any 30')
        window['-SUCCESS-'].update(font='Any 30')
        window['-S-'].update(font='Any 30')
        window['-D-'].update(font='Any 30')
        window['-PASS_PROMPT-'].update(font='Any 30')
        window['-SERVER-'].update(font='Any 30')
        window['-DNS-'].update(font='Any 30')
        large_text = True
    elif event == '-INPUT-' and large_text == True: #This reverts text to standard sizing if Enter key is hit
        window['-BROWSE-'].update(font='Any 10')
        window['-ERROR-'].update(font='Any 10')
        window['-SUCCESS-'].update(font='Any 10')
        window['-S-'].update(font='Any 10')
        window['-D-'].update(font='Any 10')
        window['-PASS_PROMPT-'].update(font='Any 10')
        window['-SERVER-'].update(font='Any 10')
        window['-DNS-'].update(font='Any 10')
        large_text = False


window.close()