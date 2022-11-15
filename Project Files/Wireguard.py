import os
import tempfile
file = "\\capstone_test.conf"
filename_only = file.replace("\\", "").replace(".conf", "")
name = tempfile.gettempdir() + file
os.system('cmd /k "wireguard /installtunnelservice %s"' % name)
#os.system('cmd /k "wireguard /uninstalltunnelservice %s"' % filename_only)