import PySimpleGUI as sg

layout = [[sg.Text('Click browse to find your configuration file'), sg.InputText(readonly=True), sg.FileBrowse('Browse', key='-FILE-')],
          [sg.Text('Enter password to decrypt file here         '), sg.InputText()],
          [sg.Button('Decrypt')],
          [sg.Text('IP Address'), sg.Input(readonly=True, key='-ADDRESS-', size=(16,1))],
          [sg.Text('DNS         '), sg.Input(readonly=True, key='-DNS-',size=(16,1))]]



window = sg.Window('Wireguard Client', layout)
var_dict = {}

def file_parser(x):
    data = x.decode().split("\n")
    for item in data:
        if "[Interface]" in item:
            item.replace("[Interface]", "")
        elif "\r" in item:
            item = item.replace("\r", "")
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value
        else:
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value

while True:
    event,values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        exit()
    elif event == 'Decrypt':
        with open(values['-FILE-'], 'rb') as test_file:
            data = test_file.read()
            file_parser(data)
            window['-ADDRESS-'].update(var_dict['Address'])
            window['-DNS-'].update(var_dict['DNS'])

window.close()