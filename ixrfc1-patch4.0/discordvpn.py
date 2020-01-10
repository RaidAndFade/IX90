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

from settings import tkns,ispchan,addr,macaddr,netmask,mtu,debug,ifup,ifdown,iface

import discord
import asyncio
import aiohttp
# from module python-pytun, NOT pytun.
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI 
import signal
from base64 import b64decode,b64encode
import os, select
import sys
from binascii import crc32
import select
from time import time
from io import BytesIO
from threading import Thread

TUNVER = "patch4.0"

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

class VPNClient():
    def __init__(self,tkns):
        self.clients = []
        self.iface = TunTapDevice(flags=IFF_TAP | IFF_NO_PI,name=iface)
        if addr is not None and netmask is not None: self.iface.addr = addr
        if addr is not None and netmask is not None: self.iface.netmask = netmask
        self.iface.hwaddr = macaddr
        self.iface.mtu = mtu
        self.iface.persist(True)
        self.iface.up()
        self.loop = asyncio.get_event_loop()
        os.system(ifup)
        self.ifacethread = IFaceThread(self.iface)
        self.ifacethread.start()
        if not sys.platform == 'win32':
            self.loop.add_signal_handler(signal.SIGINT, lambda: self.loop.stop())
            self.loop.add_signal_handler(signal.SIGTERM, lambda: self.loop.stop())

        i=0
        for tkn in tkns:
            c = VPNBot(self,self.ifacethread,i)
            i+=1
            future = asyncio.ensure_future(c.start(tkn), loop=self.loop)
            future.add_done_callback(lambda f: self.loop.stop())
            self.clients.append(c)

        self.loop.call_later(.1,self.poll_thread)
        print("Tap interface started")
        print(f"VARS: MTU{mtu}, ADDR{addr}, HWADDR{macaddr}, DSCVPN{TUNVER} - {len(tkns)} clients")
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print('Received signal to terminate bot and event loop.')
        finally:
            self.loop=asyncio.get_event_loop()
            for x in self.clients:
                asyncio.ensure_future(x.close(), loop=self.loop)
            self.loop.run_forever()
            self.ifacethread.stop()

    def is_mine(self,user):
        for x in self.clients:
            if x.user == user:
                return True
        return False

    def poll_thread(self):
        for c in self.clients:
            asyncio.ensure_future(c.send_pkts(),loop=self.loop)
        self.loop.call_later(.1,self.poll_thread)

class VPNBot(discord.Client):
    def __init__(self,net,ift,i):
        self.net = net
        self.ifacethread = ift
        self.t_id = i
        self.ready=False
        discord.Client.__init__(self)

    async def on_ready(self):
        self.chan = self.get_channel(ispchan)
        self.lastsend = time()
        self.ready=True
        self.session = aiohttp.ClientSession()
        self.macstr = ':'.join([f"{x:02x}" for x in macaddr])
        k=discord.Game(f"{self.macstr}|{self.t_id}-{TUNVER}")
        await self.change_presence(status=discord.Status.online,activity=k)
        print(f"Client {self.t_id} up: ",self.user)

    async def send_pkts(self):
        if not self.is_ready():
            return
        if len(self.ifacethread.batches)>0 and (time()-self.lastsend)>1.5:
            b = await self.ifacethread.get_batch()
            pkts,cln=b
            if debug: print(f" batch {cln} | {len(pkts)} (LB:{time()-self.lastsend}")
            self.lastsend=time()
            if cln<1480: 
                pktxt = b64encode(b''.join(pkts)).decode("utf-8")
                asyncio.ensure_future(self.chan.send(pktxt),loop=self.loop)
            else:
                fd = BytesIO()
                fc = 0
                for q in pkts:
                    if debug: print(f" send {len(q)} | {fc}")
                    fd.write(q)
                asyncio.ensure_future(self.chan.send(file=discord.File(BytesIO(fd.getvalue()),"d")),loop=self.loop)       

    async def on_message(self, message):
        if not self.ready:
            return

        if self.net.is_mine(message.author):
            return

        if message.channel.id == ispchan and self.t_id==0:
            try:
                if(len(message.attachments)==1):
                    async with self.session.get(message.attachments[0].url) as response:
                        self.ifacethread.recv_batch(await response.read())
                elif len(message.content)>0:
                    self.ifacethread.recv_batch(b64decode(message.content))
            except Exception as e:
                print(e)
                import traceback
                traceback.print_exc()
        
        if message.content == 'raidware':
            try:
                await message.channel.send(f'best ware - {self.macstr} | {self.t_id}')
            except:
                pass

VPNClient(tkns)

os.system(ifdown)