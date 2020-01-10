import logging
logging.basicConfig(level=logging.INFO)
import discord

from threading import Thread

tkn = ""
ixchn = 

def sin_basic(freq, time=3, amp=1, phase=0, samplerate=44100, bitspersample=16):
    bytelist = []
    import math
    TwoPiDivSamplerate = 2*math.pi/samplerate
    increment = TwoPiDivSamplerate * freq
    incadd = phase*increment
    for i in range(int(samplerate*time)):
        if incadd > (2**(bitspersample - 1) - 1):
            incadd = (2**(bitspersample - 1) - 1) - (incadd - (2**(bitspersample - 1) - 1))
        elif incadd < -(2**(bitspersample - 1) - 1):
            incadd = -(2**(bitspersample - 1) - 1) + (-(2**(bitspersample - 1) - 1) - incadd)
        bytelist.append(int(round(amp*(2**(bitspersample - 1) - 1)*math.sin(incadd))))
        incadd += increment
    return bytelist

def get_byte_sin(freq):
    d = sin_basic(freq)
    from functools import reduce
    return reduce(lambda a,b:a+b,[x.to_bytes(2,byteorder="little",signed=True) for x in d])

import asyncio

class DiscordVPN(discord.Client):
    def __init__(self):
        super().__init__()

    async def on_ready(self):
        self.vc = self.get_channel(ixchn)

        self.v = await self.vc.connect()
        await self.v.disconnect()
        await asyncio.sleep(1)
        self.v = await self.vc.connect()
        # data = b''.join([bytes([x]) for x in range(0,256)])
        # data=b'I am transmitting data over discord audio, semi-reliably.'
        # print(data)
        data = b"Hello world my name is raid and i fucking hate this!"
        enc = []

        from zlib import crc32
        crc = crc32(data)
        data=b'\x01'+data
        data+=crc.to_bytes(4,byteorder="little")

        # for x in data:
        #     d = b''
        #     for y in range(0,8):
        #         # one fucking bit at a time.
        #         d += (b'\xff\x00\x00\xff' if x&2**y else b'\xff\x00\xff\x00\xff\x00')
        #         if True:
        #             enc.append(d)
        #             d = b''

        fz=3840

        # data = b"abcdefghijklmnopqrstuvwxyz"
        data = b"I love soup up my sauce"
        data+=crc32(data).to_bytes(4,byteorder="little")

        enc = get_byte_sin(2)

        for x in range(0,len(data)+4,5):
            seg = data[x:x+5] 
            if len(seg)==0:
                break
            if len(seg)<5:
                seg = seg + b'\xff'*(5-len(seg))
            hdrc = b"\x80\x78" 
            hdrs = self.v.ssrc.to_bytes(4,byteorder="big")

            hdr = hdrc+seg[0:2]+(x//5).to_bytes(1,byteorder="big")+seg[2:5]+hdrs

            enc = b"\xff\x00\xff\x00"
            ence = self.v.encoder.encode(enc, self.v.encoder.SAMPLES_PER_FRAME)
            encrypt_packet = getattr(self.v, '_encrypt_' + self.v.mode)
            self.v.socket.sendto(encrypt_packet(hdr,ence), (self.v.endpoint_ip, self.v.voice_port))
            import time
            time.sleep(0.02)

            
        # self.v.send_audio_packet(enc,encode=False)
        print("!")
        # with open("sound","rb") as f:
        # #     enc=f.read()

        # # enc = [b'\xff\x00'*(data[x]+1) for x in range(len(data))]
        # # print(enc)
        # # print(len(enc))
        # import time
        # enc = get_byte_sin(150)
        # for x in range(0,4000,fz):
        #     try:
        #         self.v.send_audio_packet(enc[x:x+fz],encode=True)
        #         time.sleep(0.02)
        #     except Exception as e:
        #         print(e)
        #         print(x)
        #         break
        # # time.sleep(2)
        # for x in range(0,88200,3200):
        #     self.v.send_audio_packet(data[x:x+3200])
        #     time.sleep(0.1)

        import sys
        sys.exit(0)


client = DiscordVPN()
client.run(tkn)