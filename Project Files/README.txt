This project allows you to encrypt wireguard configuration files with a password using AES-EAX and PBDKF2

The project has 2 key parts for use:

conf_file_encrypt.py (server-side script)

This is the server-side script that can be utilised to encrypt a created WG conf file using a password of your choice.
Instructions for usage are within the script file as comments
		
-GUI.py (client side application)

This is the client-side application that allows a user to easily select an encrypted conf file they've been sent, decrypt it
by entering the correct password (also supplied by the administrator) and then connect to the VPN server. At this stage,
WireGuard for Windows must also be installed on the end-user device in order for the python application to invoke the commands
to setup the tunnel interface and connect to the VPN server

Additional packages you'll need to install from pip are:

PySimpleGUI
pycryptodome
playsound
gTTS

GUI.py contains code to provide accessibility functions as per WCAG 2.1 guidelines. The primary example is the 'speak' function.
This function reads out text provided to it using google text-to-speech. If you would like to disable this, search 'speak' within the GUI.py script and comment any speak function calls.
