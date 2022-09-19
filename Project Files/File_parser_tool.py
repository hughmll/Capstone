with open("test_conf_file.txt", "rb") as bytes_text:
    data = bytes_text.read()

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

file_parser(data)
print(var_dict)











