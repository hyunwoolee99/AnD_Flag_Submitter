#!/usr/bin/env python3
import re
import sys
from pwn import *
from time import time, sleep

# you have to modify these values
# or make config file 
RGX=re.compile(r'^RBY\{[A-Za-z0-9_]{1,64}\}$')
OK_MESSAGE = 'ok_message'
FAIL_MESSAGE = 'fail_message'
hostname = "3.35.136.43"
port_number = 7575
round_time = 5

def execute_exploit_code(actions):
    try:
        result = subprocess.run(actions, capture_output=True, text=True)
        return result.stdout.strip('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

def find_flag(output):
    if not output:
        return None
    match = RGX.search(output)
    if match:
        flag = match.group(0)
        print(flag)
        return flag
    return None

def submit_flag(flag):
    if type(flag) is not bytes:
        flag = flag.encode()
    try:
        c = remote(hostname, port_number, timeout=6)
        # c.recvuntil(b'flag >>') if needed
        c.sendline(flag)
        try:
            rep = c.recvline(timeout=6).decode(errors='replace').strip()
        except Timeout:
            rep = c.recv(timeout=1).decode(errors='replace').strip() if c else ''
        c.close()
        s = rep.lower()
        # flag success logic
        if any(x in s for x in (OK_MESSAGE)):
            print(f'ACCEPTED {flag} | {rep}')
            return 1
        # flag fail logic
        elif any(x in s for x in (FAIL_MESSAGE)) or 'expired' in s:
            print(f'REJECTED {flag} | {rep}')
        # maybe timeout logic
        else:
            print(f'UNKNOWN {flag} | {rep}')
    except (EOFError, Timeout, OSError) as e:
        print(f'ERROR submitting {flag} | {e!r}')

def polling(func):
    interval = round_time * 60
    def wrapper():
        while True:
            start = time()
            ret_val = func()
            print(ret_val)
            if ret_val != 1:
                sleep(10) # fail time interval
                continue
            elapsed = time() - start
            sleep(max(0, interval - elapsed))
    return wrapper

@polling
def main():
    try:
        action = sys.argv[1]
        actions = action.strip('\n').split(' ')
        result = execute_exploit_code(actions)
        flag = find_flag(result)
        print('flag' if flag else 'no flag')
        if flag:
            submit_flag(flag)
        
    except IndexError:
        print(f'Usage: {sys.argv[0]} <action>')
        print('Example: ')
        print(f'    {sys.argv[0]} "./exploit_code"')
        print(f'    {sys.argv[0]} "python3 exploit.py"')
        print(f'    {sys.argv[0]} "node exploit.js"')
        exit(1)

if __name__ == "__main__":
    main()