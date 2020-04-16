#!/usr/bin/env python3
import sys
import random
import pwn
pwn.context.log_level = 0


binary = './testhttp_raw'
cookie_file = 'cookies.txt'
url = 'http://localhost/example'

if len(sys.argv) > 1:
    binary = sys.argv[1]
if len(sys.argv) > 2:
    cookie_file = sys.argv[2]
if len(sys.argv) > 3:
    url = sys.argv[3]

valid_cookie = 'status=bored'
valid_multiple_cookies = 'status=bored;lookingfor=food'
invalid_cookie1 = 'status~bored'
invalid_cookie2 = 'status=bored=lazy'

def execute(application_binary, cookie_file, url, server_fn):
    out = None
    with pwn.server(callback=server_fn) as server:
        address = f'{server.lhost}:{server.lport}'
        args = [application_binary, address, cookie_file, url]
        with pwn.process(args) as client:
            out = client.readall()
    return out

def send_data(connection, data):
    connection.send(f'{len(data):x}\r\n')
    connection.send(data)
    connection.send('\r\n')

def send_cookie(connection, cookie):
    connection.send(f'Set-Cookie: {cookie}\r\n')

def non200_cb(con):
    con.readline()
    con.send('HTTP/1.1 404 Not Found\r\n\r\n')
    con.close()

def valid_cookie_cb(con):
    con.readline()
    con.send('HTTP/1.1 200 OK\r\n')
    send_cookie(con, valid_cookie)
    send_cookie(con, valid_cookie)
    send_cookie(con, valid_multiple_cookies)
    con.send('Content-Length: 0\r\n')
    con.send('\r\n')
    con.close()

def invalid_cookie_cb(con):
    con.readline()
    con.send('HTTP/1.1 200 OK\r\n')
    send_cookie(con, invalid_cookie1)
    send_cookie(con, invalid_cookie2)
    con.send('Content-Length: 0\r\n')
    con.send('\r\n')
    con.close()

def transfer_encoding_plain_cb(con):
    con.readline()
    con.send('HTTP/1.1 200 OK\r\n')
    length = 10**2
    con.send(f'Content-Length: {length}\r\n')
    con.send('\r\n')
    while length > 0:
        data = bytes([random.randrange(256) for _ in range(random.randrange(1, length+1))])
        length -= len(data)
        con.send(data)
    con.close()

def transfer_encoding_chunked_cb(con):
    con.readline()
    con.send('HTTP/1.1 200 OK\r\n')
    length = 10**2
    con.send('Transfer-Encoding: chunked\r\n')
    con.send('\r\n')
    while length > 0:
        data = bytes([random.randrange(256) for _ in range(random.randrange(1, length+1))])
        length -= len(data)
        send_data(con, data)
    send_data(con, '')
    con.close()

tests = [
    (non200_cb, b'HTTP/1.1 404 Not Found\n'),
    (valid_cookie_cb, b'status=bored\nstatus=bored\nstatus=bored\nDlugosc zasobu: 0\n'),
    (invalid_cookie_cb, None),
    (transfer_encoding_plain_cb, b'Dlugosc zasobu: 100\n'),
    (transfer_encoding_chunked_cb, b'Dlugosc zasobu: 100\n')
]

for fn, ret in tests:
    out = execute(binary, cookie_file, url, fn)
    if ret is not None and out != ret:
        print(out, ret)

