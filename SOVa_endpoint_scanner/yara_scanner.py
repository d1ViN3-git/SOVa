import os
import yara
import socket
import requests
import json
import datetime
from time import sleep
import base64
import sys
import argparse



def createParser ():
    parser = argparse.ArgumentParser()
    parser.add_argument ('-i', '--ip',required=True,help='ip-адресс сервера')
    parser.add_argument('-p', '--port',required=True,help='порт',type=int)
    return parser

def dir_scan(dir_path,rules,server_url):
    #logs_file = open("logs.txt","a+")
    dir_list=os.listdir(dir_path)
    for item in dir_list:
        if os.path.isfile(dir_path + '\\' + item):
            try:
                if rules.match(item):
                    file_path = dir_path + '\\' + item
                    json_data = {
                        "date" : str(datetime.datetime.now( ).replace(microsecond=0)),
                        "point" : socket.gethostname(),
                        "module":"yara_scanner",
                        "data" : f'''{{"file_path":"{file_path}","yara_rules":"{str(rules.match(item))}"}}
                        '''
                    }
                    #tmp = '{"date":"'+str(datetime.datetime.now( ).replace(microsecond=0))+'","point":"'+ socket.gethostname() + '", "module":"yara_scanner", "data" : "{"file_path":"' + file_path + '","yara_rules":"' 
                    #tmp = tmp + str(rules.match(item))
                    #tmp = tmp + '"}"}'
                    #print(tmp)
                    #logs_file.write(tmp)
                    print(server_url+'v1/api/sib')
                    requests.post(url=server_url+'v1/api/sib',data=json.dumps(json_data),headers={"Content-Type" : "application/json"})
            except:
                continue
        elif os.path.isdir(dir_path + '\\' + item):
            dir_scan(dir_path+'\\'+item,rules,server_url)

def yara_file_update(yar_file,server_url):
    resp = requests.get(server_url + 'v1/api/update_yara')
    response = json.loads(resp.text)
    encoded_string = response['content']
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_string = decoded_bytes.decode("utf-8")
    new_ya_file = open(response['name'],"w+")
    new_ya_file.write(decoded_string)
    if(yar_file != ''):
        os.remove(os.getcwd() + '\\' + yar_file)
    yar_file = response['name']

def find_yar_files():
    res = []
    res += [each for each in os.listdir(os.getcwd()) if each.endswith('.yar')]
    return res

def main():
    parser = createParser()
    namespace = parser.parse_args (sys.argv[1:])
    server_url='http://'+namespace.ip+':'+str(namespace.port) + '/'
    res = find_yar_files()    
    rules_path = ''
    #если в раюочей директории нет ни одного файла с расширением .yar подгружаем с сервера
    if(len(res) == 0):
        yara_file_update('',server_url)
        res = find_yar_files()    
    yar_file = res[0]
    rules_path=os.getcwd() + '\\' + yar_file
    rules = yara.compile(rules_path)
    #рекурсивное yara сканирование файлов из рабочей директории
    dir_scan(os.getcwd(),rules,server_url)
    while True:
        #проверка наличия обновления yara-правил и подгрузка их с сервера
        resp = requests.get(server_url+'v1/api/is_update_yara/' + yar_file)
        if resp.text=="false\n":
            yara_file_update(yar_file)
        sleep(3600)
        dir_scan(os.getcwd(),rules,server_url)
if __name__ == "__main__":
    main()


