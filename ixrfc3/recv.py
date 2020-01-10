import logging
logging.basicConfig(level=logging.INFO)
import discord
import dpyrecv

from threading import Thread

tkn = ""
ixchn = 
running = True

class RecvPoller(Thread):
    def __init__(self,buffer):
        Thread.__init__(self)
        self.buffer = buffer
    
    def run(self):
        global running
        while running:
            if len(self.buffer.bytearr_buf)>0:
                d=self.buffer.get_data(1000000)
                print(f"{d} DATA!")


class DataSink(dpyrecv.AudioSink):
    def __init__(self):
        self.curbyte=0
        self.data=b''

    def write(self, data):
        try:
            if isinstance(data.packet,dpyrecv.SilencePacket):
                return
            if data.user.id != 584576519406616612:
                return
            with open("out","ab+") as f:
                f.write(data.data)
            print(data.data)


        except Exception as e:
            print(e)
            print("penis")

    def wants_opus(self):
        return True

    def get_data(self, sz):
        return []
        # out = self.bytearr_buf[:sz].copy()
        # self.bytearr_buf = self.bytearr_buf[sz:]
        # return out

    # def cockinmyass()

import time
import asyncio

class DiscordVPN(discord.Client):
    def __init__(self):
        super().__init__()
        self.dataparser = DataSink()

    async def on_ready(self):
        self.vc2 = self.get_channel(584464337339547733)
        self.vc = self.get_channel(ixchn)
        
        self.v = await self.vc2.connect()
        await self.v.disconnect()
        await asyncio.sleep(1)

        # self.v = await self.vc.connect()
        self.v = await dpyrecv.prep_vc(self.vc)

        self.v.listen(self.dataparser)
        print("!")


client = DiscordVPN()
client.run(tkn)

running=False