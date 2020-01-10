#!/usr/bin/env python3.6

##################################################################################################
# IX90 License
#
# Copyright (c) 2019 RaidAndFade, A member of the The IX90 Working Group
#
# Any person or organizational entity obtaining a copy of this work and all
# associated attachments (the "Work") is hereby allowed to use the Work in any
# way, including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Work, and permit any
# other person the same rights, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Work.
#
# THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE
# WORK. IN ADDITION, WE ARE NOT RESPONSIBLE FOR ANY ROGUE TRANSHUMANIST(S)
# UPLOADING THEIR CONSCIOUSNESS(ES) TO YOUR TOASTER(S) AND BURNING YOUR PIECE(S)
# OF TOAST.
##################################################################################################
# THIS FILE SHOULD BE MODIFIED UNLESS YOU KNOW WHAT YOU ARE DOING. THIS IS PROPRIETARY SOFTWARE. 
##################################################################################################

from settings import tkn,ispchan,addr,macaddr,netmask,mtu,debug,ifup,ifdown,iface

import discord
import asyncio
import aiohttp
# from module python-pytun, NOT pytun.
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI 
from base64 import b64decode,b64encode
import os, select
import subprocess
from binascii import crc32
import select
from time import time
from random import choice
from io import BytesIO
from threading import Thread
import traceback

class IFaceThread(Thread):
    def __init__(self,iface):
        self.iface = iface
        Thread.__init__(self)

    def run(self):
        self.loop = asyncio.new_event_loop()

        self.nextpacket = None

        self.batches = []
    
        self.loop.call_later(.1,self._poll_iface)
        self.loop.run_forever()

    def stop(self):
        self.loop.stop()
        Thread._stop(self)

    def _poll_iface(self):
        r, w, e = select.select([ self.iface ], [], [], 0)
        pkts=[]
        cln = 0
        if len(self.batches) > 0:
            pkts,cln = self.batches.pop()
        while (self.iface in r or self.nextpacket is not None):
            if self.nextpacket is None:
                self.nextpacket = self.iface.read(self.iface.mtu+18)
                r, w, e = select.select([ self.iface ], [], [], 0)
            if len(self.nextpacket)+cln<3000000: # 3mb per "batch"
                crc = crc32(self.nextpacket)
                cln += len(self.nextpacket)
                cln += 4
                pkts.append(self.nextpacket+crc.to_bytes(4,byteorder="little"))
                self.nextpacket = None
            else:
                self.batches.append((pkts.copy(),cln))
                cln = 0
                pkts.clear()
        if cln > 0 and len(pkts)>0:
            self.batches.append((pkts.copy(),cln))
        self.loop.call_later(.1,self._poll_iface)

    def recv_batch(self,d):
        asyncio.ensure_future(self._recv_parse(d),loop=self.loop)

    async def _recv_parse(self,d):
        if debug: print(f" file {len(d)}")
        if debug: start = time()
        if debug: c=0
        i = BytesIO(d)
        crc = None
        chnk=b''
        k=0
        p = BytesIO()
        def check_equal(a,b):
            return a%256==b[0] and (a>>8)%256==b[1] and (a>>16)%256==b[2] and (a>>24)%256==b[3]
        while k<=mtu+18:
            cc = i.read(1)
            if cc==b'':
                break
            vc=len(chnk)==4
            if vc:
                p.write(chnk[:-3])
                crc=crc32(chnk[:-3]) if crc is None else crc32(chnk[:-3],crc)
            chnk = chnk[-3:]+cc
            k+=1
            if vc and check_equal(crc,chnk):
                q=p.getvalue()
                if debug: print(f" recv {len(q)}")
                self.iface.write(q)
                k = 0
                chnk = b''
                crc = None
                if debug: c += 1
                p = BytesIO()
        if debug: print(f"Finished reading file after {time()-start}s. found {c} pkts")

    async def get_batch(self):
        return self.batches.pop(0)

class VPNBot(discord.Client):
    def __init__(self, router, number):
        self.router = router
        self.receiver = False
        self.ready = False
        self.number = number
        super().__init__()

    async def on_ready(self):
        k=discord.Game(':'.join([f"{x:02x}" for x in macaddr]) + f'-{self.number}')
        await self.change_presence(status=discord.Status.online,activity=k)
        if self.ready:
            print('Received additional READY')
            # Ignore additional READY events
            return
        print(f'Bot {self.user} logged in')
        self.ready = True

    async def on_resume(self):
        # Set the playing status again
        k=discord.Game(':'.join([f"{x:02x}" for x in macaddr]) + f'-{self.number}')
        await self.change_presence(status=discord.Status.online,activity=k)

    async def on_message(self, message):
        if message.author == self.user:
            return

        if self.receiver and message.channel.id == ispchan:
            # if not hasattr(self,"iface"):
            #     return
            # print(f'received message {message}')
            # print(f'{self.user} is receiver: {self.receiver}')
            # print(f'self.router is {self.router}')
            try:
                await self.router.receive(message)
            except Exception as e:
                print(e)
                traceback.print_exc()
        
        if message.content == 'ping':
            try:
                t0 = time()
                msg = await message.channel.send('.')
                t1 = time()
                await msg.edit(
                    content = f'{message.author.mention} Message: {round((t1 - t0) * 1000, 2)}ms API: {round(self.latency * 1000, 2)}ms'
                )
            except Exception as e:
                try:
                    await message.channel.send(f'Failed to ping: {e}')
                except:
                    pass

class VPN:
    def run(self, tokens):
        self.loop = asyncio.get_event_loop()
        self.tokens = tokens
        self.clients = []
        self.channels = []
        self.session = None
        self.ready = False
        async def runner():
            try:
                await self.start()
            except:
                pass

        loop = asyncio.get_event_loop()

        future = asyncio.ensure_future(runner(), loop=loop)
        try:
            loop.run_forever()
        except:
            return

    async def receive(self, message):
        try:
            if(len(message.attachments)==1):
                async with aiohttp.ClientSession() as session:
                    async with session.get(message.attachments[0].url) as response:
                        d = await response.read()
                self.ifacethread.recv_batch(d)
            elif len(message.content)>0:
                self.ifacethread.recv_batch(b64decode(message.content))
        except Exception as e:
            print(e)
            traceback.print_exc()

    def send_pkts(self):
        asyncio.ensure_future(self._send_pkts(),loop=self.loop)

    async def _send_pkts(self):
        while not self.ready:
            # Wait for initialization to finish
            await asyncio.sleep(1)
            continue
        if len(self.ifacethread.batches)>0:
            b = await self.ifacethread.get_batch()
            pkts,cln=b
            if debug: print(f" batch {cln} | {len(pkts)} (LB:{time()-self.lastsend}")
            self.lastsend=time()
            channel = choice(self.channels)
            if cln<1480: 
                pktxt = b64encode(b''.join(pkts)).decode("utf-8")
                asyncio.ensure_future(channel.send(pktxt),loop=self.loop)
            else:
                fd = BytesIO()
                fc = 0
                for q in pkts:
                    if debug: print(f" send {len(q)} | {fc}")
                    fd.write(q)
                asyncio.ensure_future(channel.send(file=discord.File(BytesIO(fd.getvalue()),"d")),loop=self.loop)        
            self.loop.call_later(1.5,self.send_pkts)
        else:         
            self.loop.call_later(0.3,self.send_pkts)

    async def start(self):
        print('Starting...')

        print(f'Creating {len(self.tokens)} clients')
        for client in range(len(self.tokens)):
            print(f'Creating client #{client}')
            self.clients.append(VPNBot(self, client))

        # Set the first client as the receiver
        self.clients[0].receiver = True
        
        for client, token in enumerate(self.tokens):
            print(f'Starting client #{client} with token {token}')
            self.loop.create_task(self.clients[client].start(token))
        
        self.session = aiohttp.ClientSession()
        self.iface = TunTapDevice(flags=IFF_TAP | IFF_NO_PI,name=iface)
        if addr is not None and netmask is not None:
            self.iface.addr = addr
        if addr is not None and netmask is not None:
            self.iface.netmask = netmask
        self.iface.hwaddr = macaddr
        self.iface.mtu = mtu
        self.iface.persist(True)
        self.iface.up()
        os.system(ifup)
        self.ifacethread = IFaceThread(self.iface)
        self.ifacethread.start()
        self.lastsend = time()
        print("Tap interface started")
        print(f"VARS: MTU{mtu}, ADDR{addr}, HWADDR{macaddr}")
        self.loop.call_later(.1,self.send_pkts)

        while any(client.ready == False for client in self.clients):
            # Wait for all clients to come up
            await asyncio.sleep(1)
            continue

        self.channels = [client.get_channel(ispchan) for client in self.clients]
        self.ready = True

client = VPN()
client.run(tkn)

os.system(ifdown)