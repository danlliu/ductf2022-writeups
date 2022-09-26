
# jslock
DownUnder CTF 2022; Rev (Easy)

Writeup by danlliu from WolvSec (solved)

## General Approach

Here, we are given a HTML file `js-lock.html` with some JavaScript code. Our goal is to find the correct key for the `win` function, which takes the SHA-512 hash of the key and XORs it with a predetermined array to give the flag.

## Solution

The `js-lock.html` file is shown below, with CSS hidden for clarity and the base64 string for `LOCK` removed, also for clarity.

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <title>js lock</title>

        <style>
          ... css ...
        </style>
    </head>

    <div class="bg"></div>
    <body>

        <div class="container">
            <div>
                Pin:
                <b><span id="current-pin">1</span></b>
            </div>

            <div id="current-attempt">
                Starting cracking the lock...
            </div>

            <div id="status">
                ???
            </div>

            <div class="hstack">
                <button id="btn-0" onclick="hit_0()">0</button>

                <button id="btn-1" onclick="hit_1()">1</button>
            </div>

            <button id="submit" onclick="submit_pin()">Unlock</button>
        </div>

        <script>
            const LOCK = eval(atob(<very long base64 string>))
            const C = [62, 223, 233, 153, 37, 113, 79, 195, 9, 58, 83, 39, 245, 213, 253, 138, 225, 232, 123, 90, 8, 98, 105, 1, 31, 198, 67, 83, 41, 139, 118, 138, 252, 165, 214, 158, 116, 173, 174, 161, 6, 233, 37, 35, 86, 7, 108, 223, 97, 251, 2, 245, 129, 118, 227, 120, 26, 70, 40, 26, 183, 90, 172, 155]

            function set_status(s) {
                document.getElementById('status').innerHTML = s
            }

            function disable() {
                document.getElementById('btn-0').disabled = true
                document.getElementById('btn-1').disabled = true
                document.getElementById('submit').disabled = true
            }

            function sha512(m) {
                return crypto.subtle.digest('SHA-512', new TextEncoder('utf-8').encode(m))
                    .then((b) => new Uint8Array(b))
            }

            const S = { current: 1, key: '', T: LOCK, idx: 0 }

            function hit_0() {
                S.key += '0'
                if(typeof S.T != 'object' || S.T[S.idx] == undefined) {
                    set_status(`<div style="color: red">Pin ${S.current} is stuck!</div>`)
                    disable()
                } else {
                    S.T = S.T[S.idx]
                    S.idx = 0
                    document.getElementById('current-attempt').innerText = S.key
                }
            }

            function hit_1() {
                S.key += '1'
                S.idx += 1
                document.getElementById('current-attempt').innerText = S.key
            }

            function submit_pin() {
                S.idx = 0
                if(S.T === S.current) {
                    set_status(`<div style="color: green">Pin ${S.current} unlocked!</div>`)

                    if(S.current == 1337) {
                        win()
                    } else {
                        S.current += 1
                        document.getElementById("current-pin").innerText = S.current
                        S.T = LOCK
                    }
                } else {
                    set_status(`<div style="color: red">Pin ${S.current} didn\'t unlock!</div>`)
                    disable()
                }
            }

            async function win() {
                const K = await sha512(S.key)
                const dec = []
                for(var i = 0; i < 64; i++) {
                    dec.push(String.fromCodePoint(C[i] ^ K[i]))
                }
                const flag = dec.join('')
                set_status(flag)
            }

        </script>
    </body>
</html>
```

When I opened this file in my browser, I got a `Maximum call stack size exceeded` error (interestingly enough, no mention of this error was ever found in the official solution). Attempting to execute the array in Python also led to an error due to the number of nested arrays. Thus, I chose to manually parse the array, keeping track of where different elements were present. The script is shown below. (if you'd like to see the full nested array, check out the full file at [solve.py](jslock-solve.py))

```python
import re

s = '[0, 0, <very long nested array>]'

m = {}
nested = []

while len(s) > 0:
    if s[0] == ',':
        nested[-1] += 1
        s = s[1:]
    elif s[0] == '[':
        nested.append(0)
        s = s[1:]
    elif s[0] == ']':
        nested = nested[:-1]
        s = s[1:]
    elif s[0] == ' ':
        s = s[1:]
    else:
        n = re.compile('([0-9]+)')
        ma = n.match(s)
        m[ma.groups(0)[0]] = [x for x in nested]
        s = s[len(ma.groups(0)[0]):]
```

Now that we know where elements are present, we can take a look at the logic for generating the key. We have two functions: `hit_0` and `hit_1`, which correspond to pressing the `0` and `1` buttons respectively. Additionally, we have `submit_pin`, which calls `win` when `S.current` reaches `1337`. We see that `S.current` starts at 1, and increments by `1` each time `submit_pin` is called (if the `if` statement condition passes). Thus, we have to solve `1337` pins. To increment our pin by `1`, we need to ensure that `S.T` is equal to `S.current`. This is where `hit_0` and `hit_1` come into play. Let's start with `hit_1`, since it's shorter. `hit_1` increases `S.idx` by 1, and adds `1` to the key. The value of `S.idx` is used in `hit_0`, where we index into the current value of `S.T` by `S.idx` and set `S.T` to that value. If `S.T` is not an object or undefined (if we tried to index into a number, for example), the lock is disabled and we have to start over.

From this, we can work out a strategy to reach any element. Let's consider a very simple example, where `LOCK = [0, [1, 0, 2]]`. To access the element `1`, we have to index `LOCK[1][0]`. Thus, we can use the following sequence of numbers:

```
1: S.idx = 1
0: S.T = [1, 0, 2]; S.idx = 0
0: S.T = 1; S.idx = 0
```

To access the element `2`, we have to index `LOCK[1][2]`. Thus, we can use the following sequence:

```
1: S.idx = 1
0: S.T = [1, 0, 2]; S.idx = 0
1: S.idx = 1
1; S.idx = 2
0; S.T = 2; S.idx = 0
```

In general, for each index `i` at each "level" of the array, we have to input `i` `1`s, followed by a `0`. Thus, we can derive the key, and decrypt the flag, as shown below!

```python
result = ''

for i in range(1, 1338):
    a = m[str(i)]
    s = ''
    for j in a:
        s += '1' * j
        s += '0'
    result += s

from Crypto.Hash import SHA512

h = SHA512.new()
h.update(result.encode('utf-8'))
hd = h.hexdigest()

C = [62, 223, 233, 153, 37, 113, 79, 195, 9, 58, 83, 39, 245, 213, 253, 138, 225, 232, 123, 90, 8, 98, 105, 1, 31, 198, 67, 83, 41, 139, 118, 138, 252, 165, 214, 158, 116, 173, 174, 161, 6, 233, 37, 35, 86, 7, 108, 223, 97, 251, 2, 245, 129, 118, 227, 120, 26, 70, 40, 26, 183, 90, 172, 155]
T = bytes.fromhex(hd)

print(''.join(chr(c ^ t) for c, t in zip(C, T)))
```

Solution: `DUCTF{s3arch1ng_thr0ugh_an_arr4y_1s_n0t_th4t_h4rd_ab894d8dfea17}`

It really isn't that hard ;)
