#this file is literally a stripped down version of imayhaveborkedit's audioreceiver
import ctypes
import ctypes.util
import time
import wave
import select
import socket
import logging
import threading
import traceback
import array
import sys
import os
import bisect
import struct
import math
import asyncio

from collections import defaultdict, namedtuple
# from .rtp import SilencePacket
from discord.gateway import DiscordVoiceWebSocket
from discord import utils
from discord import VoiceClient, DiscordException, ClientException, ConnectionClosed
from types import MethodType

async def vc_connect_override(self, *, reconnect=True, _tries=0, do_handshake=True):
    log.info('Connecting to voice...')
    try:
        del self.secret_key
    except AttributeError:
        pass

    if do_handshake:
        await self.start_handshake()

    try:
        self.ws = await DiscordVoiceWebSocket.from_client(self)
        self._handshaking = False
        self._connected.clear()
        self.ws.oldrcv = self.ws.received_message
        async def received_message(self, msg):
            op = msg['op']
            data = msg.get('d')
            if op == 5: #speaking
                log.info("Someone speaking!")
                user_id = int(data['user_id'])
                vc = self._connection
                vc._ssrcs[user_id] = data['ssrc']
            else:
                await self.oldrcv(msg)
                if op == 4: # description
                    log.info("Sending fake silence.")
                    await self.speak()
                    await asyncio.sleep(0.5)
                    self._connection.send_audio_packet(b'\xF8\xFF\xFE', encode=False)
                    await self.speak(False)
        self.ws.received_message = MethodType(received_message,self.ws)
        while not hasattr(self, 'secret_key'):
            await self.ws.poll_event()
        self._connected.set()
    except (ConnectionClosed, asyncio.TimeoutError):
        if reconnect and _tries < 5:
            log.exception('Failed to connect to voice... Retrying...')
            await asyncio.sleep(1 + _tries * 2.0, loop=self.loop)
            await self.terminate_handshake()
            await self.connect(reconnect=reconnect, _tries=_tries + 1)
        else:
            raise

    if self._runner is None:
        self._runner = self.loop.create_task(self.poll_voice_ws(reconnect))

async def prep_vc(vc):
    key_id, _ = vc._get_voice_client_key()
    state = vc._state

    if state._get_voice_client(key_id):
        raise ClientException('Already connected to a voice channel.')

    v = VoiceClient(state=state, timeout=60, channel=vc)
    state._add_voice_client(key_id, v)

    v.listen = MethodType(vc_listen_override,v)
    v.connect = MethodType(vc_connect_override,v)
    v._ssrcs = Bidict()
    try:
        await v.connect()
    except asyncio.TimeoutError:
        try:
            await v.disconnect(force=True)
        except Exception:
            # we don't care if disconnect failed because connection failed
            pass
        raise # re-raise

    return v


class Bidict(dict):
    """A bi-directional dict"""
    _None = object()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        super().update({v:k for k, v in self.items()})

    def __setitem__(self, key, value):
        # Delete related mappings
        # if we have 1 <-> 2 and we set 2 <-> 3, 2 is now unrelated to 1

        if key in self:
            del self[key]
        if value in self:
            del self[value]

        super().__setitem__(key, value)
        super().__setitem__(value, key)

    def __delitem__(self, key):
        value = super().__getitem__(key)
        super().__delitem__(value)

        if key == value:
            return

        super().__delitem__(key)

    def to_dict(self):
        return super().copy()

    def pop(self, k, d=_None):
        try:
            v = super().pop(k)
            super().pop(v, d)
            return v
        except KeyError:
            if d is not self._None:
                return d
            raise

    def popitem(self):
        item = super().popitem()
        super().__delitem__(item[1])
        return item

    def setdefault(self, k, d=None):
        try:
            return self[k]
        except KeyError:
            if d in self:
                return d

        self[k] = d
        return d

    def update(self, *args, **F):
        try:
            E = args[0]
            if callable(getattr(E, 'keys', None)):
                for k in E:
                    self[k] = E[k]
            else:
                for k,v in E:
                    self[k] = v
        except IndexError:
            pass
        finally:
            for k in F:
                self[k] = F[k]

    def copy(self):
        return self.__class__(super().copy())

    # incompatible
    # https://docs.python.org/3/library/exceptions.html#NotImplementedError, Note 1
    fromkeys = None

def decode(data):
    """Creates an :class:`RTPPacket` or an :class:`RTCPPacket`.
    Parameters
    -----------
    data : bytes
        The raw packet data.
    """

    # While technically unreliable, discord RTP packets (should)
    # always be distinguishable from RTCP packets.  RTCP packets
    # should always have 200-204 as their second byte, while RTP
    # packet are (probably) always 73 (or at least not 200-204).

    assert data[0] >> 6 == 2 # check version bits
    return _rtcp_map.get(data[1], RTPPacket)(data)

def is_rtcp(data):
    return 200 <= data[1] <= 204

def _parse_low(x):
    return x / 2.0 ** x.bit_length()

def vc_listen_override(self,sink):
    if not self.is_connected():
        raise ClientException('Not connected to voice.')

    if not isinstance(sink, AudioSink):
        raise TypeError('sink must be an AudioSink not {0.__class__.__name__}'.format(sink))

    if hasattr(self,"_reader") and self._reader is not None and self._reader.is_listening():
        raise ClientException('Already receiving audio.')

    self._reader = AudioReader(sink, self)
    self._reader.start()

class Defaultdict(defaultdict):
    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError((key,))

        self[key] = value = self.default_factory(key)
        return value

class AudioSink:
    def __del__(self):
        self.cleanup()

    def write(self, data):
        raise NotImplementedError

    def wants_opus(self):
        return False

    def cleanup(self):
        pass

try:
    import nacl.secret
    from nacl.exceptions import CryptoError
except ImportError:
    pass

log = logging.getLogger(__name__)
log.warn("penis")
c_int_ptr   = ctypes.POINTER(ctypes.c_int)
c_int16_ptr = ctypes.POINTER(ctypes.c_int16)
c_float_ptr = ctypes.POINTER(ctypes.c_float)

class EncoderStruct(ctypes.Structure):
    pass

class DecoderStruct(ctypes.Structure):
    pass

OK      = 0
BAD_ARG = -1

# Encoder CTLs
APPLICATION_AUDIO    = 2049
APPLICATION_VOIP     = 2048
APPLICATION_LOWDELAY = 2051

CTL_SET_BITRATE      = 4002
CTL_SET_BANDWIDTH    = 4008
CTL_SET_FEC          = 4012
CTL_SET_PLP          = 4014
CTL_SET_SIGNAL       = 4024

# Decoder CTLs
CTL_SET_GAIN             = 4034
CTL_LAST_PACKET_DURATION = 4039

EncoderStructPtr = ctypes.POINTER(EncoderStruct)
DecoderStructPtr = ctypes.POINTER(DecoderStruct)

def _err_lt(result, func, args):
    if result < OK:
        log.info('error has happened in %s', func.__name__)
        raise OpusError(result)
    return result

def _err_ne(result, func, args):
    ret = args[-1]._obj
    if ret.value != OK:
        log.info('error has happened in %s', func.__name__)
        raise OpusError(ret.value)
    return result

def libopus_loader(name):
    # create the library...
    lib = ctypes.cdll.LoadLibrary(name)

    # register the functions...
    for item in exported_functions:
        func = getattr(lib, item[0])

        try:
            if item[1]:
                func.argtypes = item[1]

            func.restype = item[2]
        except KeyError:
            pass

        try:
            if item[3]:
                func.errcheck = item[3]
        except KeyError:
            log.info("Error assigning check function to %s", item[0])

    return lib

class OpusError(DiscordException):
    """An exception that is thrown for libopus related errors.
    Attributes
    ----------
    code: :class:`int`
        The error code returned.
    """

    def __init__(self, code):
        self.code = code
        msg = _lib.opus_strerror(self.code).decode('utf-8')
        log.info('"%s" has happened', msg)
        super().__init__(msg)

band_ctl = {
    'narrow': 1101,
    'medium': 1102,
    'wide': 1103,
    'superwide': 1104,
    'full': 1105,
}

signal_ctl = {
    'auto': -1000,
    'voice': 3001,
    'music': 3002,
}
# A list of exported functions.
# The first argument is obviously the name.
# The second one are the types of arguments it takes.
# The third is the result type.
# The fourth is the error handler.
exported_functions = [
    ('opus_strerror',
        [ctypes.c_int], ctypes.c_char_p, None),
    ('opus_packet_get_bandwidth',
        [ctypes.c_char_p], ctypes.c_int, _err_lt),
    ('opus_packet_get_nb_channels',
        [ctypes.c_char_p], ctypes.c_int, _err_lt),
    ('opus_packet_get_nb_frames',
        [ctypes.c_char_p, ctypes.c_int], ctypes.c_int, _err_lt),
    ('opus_packet_get_samples_per_frame',
        [ctypes.c_char_p, ctypes.c_int], ctypes.c_int, _err_lt),

    ('opus_encoder_get_size',
        [ctypes.c_int], ctypes.c_int, None),
    ('opus_encoder_create',
        [ctypes.c_int, ctypes.c_int, ctypes.c_int, c_int_ptr], EncoderStructPtr, _err_ne),
    ('opus_encode',
        [EncoderStructPtr, c_int16_ptr, ctypes.c_int, ctypes.c_char_p, ctypes.c_int32], ctypes.c_int32, _err_lt),
    ('opus_encoder_ctl',
        None, ctypes.c_int32, _err_lt),
    ('opus_encoder_destroy',
        [EncoderStructPtr], None, None),

    ('opus_decoder_get_size',
        [ctypes.c_int], ctypes.c_int, None),
    ('opus_decoder_create',
        [ctypes.c_int, ctypes.c_int, c_int_ptr], DecoderStructPtr, _err_ne),
    ('opus_decoder_get_nb_samples',
        [DecoderStructPtr, ctypes.c_char_p, ctypes.c_int32], ctypes.c_int, _err_lt),
    ('opus_decode',
        [DecoderStructPtr, ctypes.c_char_p, ctypes.c_int32, c_int16_ptr, ctypes.c_int, ctypes.c_int],
        ctypes.c_int, _err_lt),
    ('opus_decoder_ctl',
        None, ctypes.c_int32, _err_lt),
    ('opus_decoder_destroy',
        [DecoderStructPtr], None, None)
]
def load_opus(name):
    """Loads the libopus shared library for use with voice.
    If this function is not called then the library uses the function
    `ctypes.util.find_library`__ and then loads that one
    if available.
    .. _find library: https://docs.python.org/3.5/library/ctypes.html#finding-shared-libraries
    __ `find library`_
    Not loading a library leads to voice not working.
    This function propagates the exceptions thrown.
    .. note::
        On Windows, this function should not need to be called as the binaries
        are automatically loaded.
    .. warning::
        The bitness of the library must match the bitness of your python
        interpreter. If the library is 64-bit then your python interpreter
        must be 64-bit as well. Usually if there's a mismatch in bitness then
        the load will throw an exception.
    .. note::
        On Windows, the .dll extension is not necessary. However, on Linux
        the full extension is required to load the library, e.g. ``libopus.so.1``.
        On Linux however, `find library`_ will usually find the library automatically
        without you having to call this.
    Parameters
    ----------
    name: :class:`str`
        The filename of the shared library.
    """
    global _lib
    _lib = libopus_loader(name)
class _OpusStruct:
    SAMPLING_RATE = 48000
    CHANNELS = 2
    FRAME_LENGTH = 20 # in ms
    SAMPLE_SIZE = 4 # (bit_rate / 8) * CHANNELS (bit_rate == 16)
    SAMPLES_PER_FRAME = int(SAMPLING_RATE / 1000 * FRAME_LENGTH)

    FRAME_SIZE = SAMPLES_PER_FRAME * SAMPLE_SIZE
def is_loaded():
    """Function to check if opus lib is successfully loaded either
    via the ``ctypes.util.find_library`` call of :func:`load_opus`.
    This must return ``True`` for voice to work.
    Returns
    -------
    :class:`bool`
        Indicates if the opus library has been loaded.
    """
    global _lib
    return _lib is not None
class OpusNotLoaded(DiscordException):
    """An exception that is thrown for when libopus is not loaded."""
    pass
class Decoder(_OpusStruct):
    def __init__(self):
        if not is_loaded():
            raise OpusNotLoaded()

        self._state = self._create_state()

    def __del__(self):
        if hasattr(self, '_state'):
            _lib.opus_decoder_destroy(self._state)
            self._state = None

    def _create_state(self):
        ret = ctypes.c_int()
        return _lib.opus_decoder_create(self.SAMPLING_RATE, self.CHANNELS, ctypes.byref(ret))

    @staticmethod
    def packet_get_nb_frames(data):
        """Gets the number of frames in an Opus packet"""
        return _lib.opus_packet_get_nb_frames(data, len(data))

    @staticmethod
    def packet_get_nb_channels(data):
        """Gets the number of channels in an Opus packet"""
        return _lib.opus_packet_get_nb_channels(data)

    @classmethod
    def packet_get_samples_per_frame(cls, data):
        """Gets the number of samples per frame from an Opus packet"""
        return _lib.opus_packet_get_samples_per_frame(data, cls.SAMPLING_RATE)

    def _set_gain(self, adjustment):
        """Configures decoder gain adjustment.
        Scales the decoded output by a factor specified in Q8 dB units.
        This has a maximum range of -32768 to 32767 inclusive, and returns
        OPUS_BAD_ARG (-1) otherwise. The default is zero indicating no adjustment.
        This setting survives decoder reset (irrelevant for now).
        gain = 10**x/(20.0*256)
        (from opus_defines.h)
        """
        return _lib.opus_decoder_ctl(self._state, CTL_SET_GAIN, adjustment)

    def set_gain(self, dB):
        """Sets the decoder gain in dB, from -128 to 128."""

        dB_Q8 = max(-32768, min(32767, round(dB * 256))) # dB * 2^n where n is 8 (Q8)
        return self._set_gain(dB_Q8)

    def set_volume(self, mult):
        """Sets the output volume as a float percent, i.e. 0.5 for 50%, 1.75 for 175%, etc."""
        return self.set_gain(20 * math.log10(mult)) # amplitude ratio

    def _get_last_packet_duration(self):
        """Gets the duration (in samples) of the last packet successfully decoded or concealed."""

        ret = ctypes.c_int32()
        _lib.opus_decoder_ctl(self._state, CTL_LAST_PACKET_DURATION, ctypes.byref(ret))
        return ret.value

    def decode(self, data, *, fec=False):
        if data is None and fec:
            raise OpusError("Invalid arguments: FEC cannot be used with null data")

        if data is None:
            frame_size = self._get_last_packet_duration() or self.SAMPLES_PER_FRAME
        else:
            frames = self.packet_get_nb_frames(data)
            samples_per_frame = self.packet_get_samples_per_frame(data)
            frame_size = frames * samples_per_frame

        pcm = (ctypes.c_int16 * (frame_size * self.CHANNELS))()
        pcm_ptr = ctypes.cast(pcm, ctypes.POINTER(ctypes.c_int16))

        result = _lib.opus_decode(self._state, data, len(data) if data else 0, pcm_ptr, frame_size, fec)
        return array.array('h', pcm).tobytes()

try:
    if sys.platform == 'win32':
        _basedir = os.path.dirname(os.path.abspath(__file__))
        _bitness = 'x64' if sys.maxsize > 2**32 else 'x86'
        _filename = os.path.join(_basedir, 'bin', 'libopus-0.{}.dll'.format(_bitness))
        _lib = libopus_loader(_filename)
    else:
        _lib = libopus_loader(ctypes.util.find_library('opus'))
except Exception as e:
    _lib = None
    log.warning("Unable to load opus lib, %s", e)

class _PacketCmpMixin:
    __slots__ = ()

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def __gt__(self, other):
        return self.timestamp > other.timestamp

    def __eq__(self, other):
        return self.timestamp == other.timestamp

class SilencePacket(_PacketCmpMixin):
    __slots__ = ('ssrc', 'timestamp')
    decrypted_data = b'\xF8\xFF\xFE'

    def __init__(self, ssrc, timestamp):
        self.ssrc = ssrc
        self.timestamp = timestamp

    def __repr__(self):
        return '<SilencePacket timestamp={0.timestamp}, ssrc={0.ssrc}>'.format(self)

class FECPacket(_PacketCmpMixin):
    __slots__ = ('ssrc', 'timestamp', 'sequence')
    decrypted_data = b''

    def __init__(self, ssrc, timestamp, sequence):
        self.ssrc = ssrc
        self.timestamp = sequence
        self.sequence = timestamp

    def __repr__(self):
        return '<FECPacket timestamp={0.timestamp}, sequence={0.sequence}, ssrc={0.ssrc}>'.format(self)

# Consider adding silence attribute to differentiate (to skip isinstance)

class RTPPacket(_PacketCmpMixin):
    __slots__ = ('version', 'padding', 'extended', 'cc', 'marker',
                 'payload', 'sequence', 'timestamp', 'ssrc', 'csrcs',
                 'header', 'data', 'decrypted_data', 'extension')

    _hstruct = struct.Struct('>xxHII')
    _ext_header = namedtuple("Extension", 'profile length values')

    def __init__(self, data):
        data = bytearray(data)

        self.version  =      data[0] >> 6
        self.padding  = bool(data[0] & 0b00100000)
        self.extended = bool(data[0] & 0b00010000)
        self.cc       =      data[0] & 0b00001111

        self.marker   = bool(data[1] & 0b10000000)
        self.payload  =      data[1] & 0b01111111

        self.sequence, self.timestamp, self.ssrc = self._hstruct.unpack_from(data)

        self.csrcs = ()
        self.extension = None

        self.header = data[:12]
        self.data = data[12:]
        self.decrypted_data = None

        if self.cc:
            fmt = '>%sI' % self.cc
            offset = struct.calcsize(fmt) + 12
            self.csrcs = struct.unpack(fmt, data[12:offset])
            self.data = data[offset:]

        # TODO?: impl padding calculations (though discord doesn't seem to use that bit)

    def update_ext_headers(self, data):
        """Adds extended header data to this packet, returns payload offset"""

        profile, length = struct.unpack_from('>HH', data)
        values = struct.unpack('>%sI' % length, data[4:4+length*4])
        self.extension = self._ext_header(profile, length, values)

        # TODO?: Update self.data with new data offset
        # ... (do I need to do this? because it seems to work fine without it)

        return 4 + length * 4

    def _dump_info(self):
        attrs = {name: getattr(self, name) for name in self.__slots__}
        return ''.join((
            "<RTPPacket ",
            *['{}={}, '.format(n, v) for n, v in attrs.items()],
            '>'))

    def __repr__(self):
        return '<RTPPacket ext={0.extended}, ' \
               'timestamp={0.timestamp}, sequence={0.sequence}, ' \
               'ssrc={0.ssrc}, size={1}' \
               '>'.format(self, len(self.data))

# http://www.rfcreader.com/#rfc3550_line855
class RTCPPacket(_PacketCmpMixin):
    __slots__ = ('version', 'padding', 'length')
    _header = struct.Struct('>BBH')
    _ssrc_fmt = struct.Struct('>I')
    type = None

    def __init__(self, data):
        head, _, self.length = self._header.unpack_from(data)
        self.version = head >> 6
        self.padding = bool(head & 0b00100000)
        # dubious, yet devious
        setattr(self, self.__slots__[0], head & 0b00011111)

    def __repr__(self):
        content = ', '.join("{}: {}".format(k, getattr(self, k, None)) for k in self.__slots__)
        return "<{} {}>".format(self.__class__.__name__, content)

    @classmethod
    def from_data(cls, data):
        _, ptype, _ = cls._header.unpack_from(data)
        return _rtcp_map[ptype](data)

# TODO?: consider moving repeated code to a ReportPacket type
# http://www.rfcreader.com/#rfc3550_line1614
class SenderReportPacket(RTCPPacket):
    __slots__ = ('report_count', 'ssrc', 'info', 'reports', 'extension')
    _info_fmt = struct.Struct('>5I')
    _report_fmt = struct.Struct('>IB3x4I')
    _24bit_int_fmt = struct.Struct('>4xI')
    _info = namedtuple('RRSenderInfo', 'ntp_ts rtp_ts packet_count octet_count')
    _report = namedtuple("RReport", 'ssrc perc_loss total_lost last_seq jitter lsr dlsr')
    type = 200

    def __init__(self, data):
        super().__init__(data)
        self.ssrc = self._ssrc_fmt.unpack_from(data, 4)[0]
        self.info = self._read_sender_info(data, 8)

        reports = []
        for x in range(self.report_count):
            offset = 28 + 24 * x
            reports.append(self._read_report(data, offset))

        self.reports = tuple(reports)

        if len(data) > 28 + 24*self.report_count:
            self.extension = data[28 + 24*self.report_count:]

    def _read_sender_info(self, data, offset):
        nhigh, nlow, rtp_ts, pcount, ocount = self._info_fmt.unpack_from(data, offset)
        ntotal = nhigh + _parse_low(nlow)
        return self._info(ntotal, rtp_ts, pcount, ocount)

    def _read_report(self, data, offset):
        ssrc, flost, seq, jit, lsr, dlsr = self._report_fmt.unpack_from(data, offset)
        clost = self._24bit_int_fmt.unpack_from(data, offset)[0] & 0xFFFFFF
        return self._report(ssrc, flost, clost, seq, jit, lsr, dlsr)

# http://www.rfcreader.com/#rfc3550_line1879
class ReceiverReportPacket(RTCPPacket):
    __slots__ = ('report_count', 'ssrc', 'reports', 'extension')
    _report_fmt = struct.Struct('>IB3x4I')
    _24bit_int_fmt = struct.Struct('>4xI')
    _report = namedtuple("RReport", 'ssrc perc_loss total_lost last_seq jitter lsr dlsr')
    type = 201

    def __init__(self, data):
        super().__init__(data)
        self.ssrc = self._ssrc_fmt.unpack_from(data, 4)[0]

        reports = []
        for x in range(self.report_count):
            offset = 8 + 24 * x
            reports.append(self._read_report(data, offset))

        self.reports = tuple(reports)

        if len(data) > 8 + 24*self.report_count:
            self.extension = data[8 + 24*self.report_count:]

    def _read_report(self, data, offset):
        ssrc, flost, seq, jit, lsr, dlsr = self._report_fmt.unpack_from(data, offset)
        clost = self._24bit_int_fmt.unpack_from(data, offset)[0] & 0xFFFFFF
        return self._report(ssrc, flost, clost, seq, jit, lsr, dlsr)

# UNFORTUNATELY it seems discord only uses the above two packet types.
# Good thing I knew that when I made the rest of these. Haha yes.

# http://www.rfcreader.com/#rfc3550_line2024
class SDESPacket(RTCPPacket):
    __slots__ = ('source_count', 'chunks', '_pos')
    _item_header = struct.Struct('>BB')
    _chunk = namedtuple("SDESChunk", 'ssrc items')
    _item = namedtuple("SDESItem", 'type size length text')
    type = 202

    def __init__(self, data):
        super().__init__(data)
        _chunks = []
        self._pos = 4

        for x in range(self.source_count):
            _chunks.append(self._read_chunk(data))

        self.chunks = tuple(_chunks)

    def _read_chunk(self, data):
        ssrc = self._ssrc_fmt.unpack_from(data, self._pos)[0]
        self._pos += 4

        # check for chunk with no items
        if data[self._pos:self._pos+4] == b'\x00\x00\x00\x00':
            self._pos += 4
            return self._chunk(ssrc, ())

        items = [self._read_item(data)]

        # Read items until END type is found
        while items[-1].type != 0:
            items.append(self._read_item(data))

        # pad chunk to 4 bytes
        if self._pos % 4:
            self._pos = ceil(self._pos/4)*4

        return self._chunk(ssrc, items)

    def _read_item(self, data):
        itype, ilen = self._item_header.unpack_from(data, self._pos)
        self._pos += 2
        text = None

        if ilen:
            text = data[self._pos:self._pos+ilen].decode()
            self._pos += ilen

        return self._item(itype, ilen+2, ilen, text)

    def _get_chunk_size(self, chunk):
        return 4 + max(4, sum(i.size for i in chunk.items)) # + padding?

# http://www.rfcreader.com/#rfc3550_line2311
class BYEPacket(RTCPPacket):
    __slots__ = ('source_count', 'ssrcs', 'reason')
    type = 203

    def __init__(self, data):
        super().__init__(data)
        self.ssrcs = struct.unpack_from('>%sI' % self.source_count, data, 4)
        self.reason = None

        body_length = 4 + len(self.ssrcs) * 4
        if len(data) > body_length:
            extra_len = struct.unpack_from('B', data, body_length)[0]
            reason = struct.unpack_from('%ss' % extra_len, data, body_length + 1)
            self.reason = reason.decode()

# http://www.rfcreader.com/#rfc3550_line2353
class APPPacket(RTCPPacket):
    __slots__ = ('subtype', 'ssrc', 'name', 'data')
    _packet_info = struct.Struct('>I4s')
    type = 204

    def __init__(self, data):
        super().__init__(data)
        self.ssrc, name = self._packet_info.unpack_from(data, 4)
        self.name = name.decode('ascii')
        self.data = data[12:] # should be a multiple of 32 bits but idc

_rtcp_map = {
    200: SenderReportPacket,
    201: ReceiverReportPacket,
    202: SDESPacket,
    203: BYEPacket,
    204: APPPacket
}
class SinkExit(DiscordException):
    """A signal type exception (like ``GeneratorExit``) to raise in a Sink's write() method to stop it.
    TODO: make better words
    Parameters
    -----------
    drain: :class:`bool`
        ...
    flush: :class:`bool`
        ...
    """

    def __init__(self, *, drain=True, flush=False):
        self.kwargs = kwargs
class VoiceData:
    __slots__ = ('data', 'user', 'packet')

    def __init__(self, data, user, packet):
        self.data = data
        self.user = user
        self.packet = packet
class BufferedDecoder(threading.Thread):
    DELAY = Decoder.FRAME_LENGTH / 1000.0

    def __init__(self, ssrc, output_func, *, buffer=200):
        super().__init__(daemon=True, name='ssrc-%s' % ssrc)

        if buffer < 40: # technically 20 works but then FEC is useless
            raise ValueError("buffer size of %s is invalid; cannot be lower than 40" % buffer)

        self.ssrc = ssrc
        self.output_func = output_func

        self._decoder = Decoder()
        self._buffer = []
        self._last_seq = 0
        self._last_ts = 0
        self._loops = 0

        # Optional diagnostic state stuff
        self._overflow_mult = self._overflow_base = 2.0
        self._overflow_incr = 0.5

        # minimum (lower bound) size of the jitter buffer (n * 20ms per packet)
        self.buffer_size = buffer // self._decoder.FRAME_LENGTH

        self._finalizing = False
        self._end_thread = threading.Event()
        self._end_main_loop = threading.Event()
        self._primed = threading.Event()
        self._lock = threading.RLock()

        # TODO: Add RTCP queue
        self._rtcp_buffer = []

        self.start()

    def feed_rtp(self, packet):
        if self._last_ts < packet.timestamp:
            self._push(packet)
        elif self._end_thread.is_set():
            return

    def feed_rtcp(self, packet):
        ... # TODO: rotating buffer of Nones or something
        #           or I can store (last_seq + buffer_size, packet)
        # print(f"[router:feed] Got rtcp packet {packet}")
        # print(f"[router:feed] Other timestamps: {[p.timestamp for p in self._buffer]}")
        # print(f"[router:feed] Other timestamps: {self._buffer}")

    def truncate(self, *, size=None):
        """Discards old data to shrink buffer back down to ``size`` (default: buffer_size).
        TODO: doc
        """

        size = self.buffer_size if size is None else size
        with self._lock:
            self._buffer = self._buffer[-size:]

    def stop(self, **kwargs):
        """
        drain=True: continue to write out the remainder of the buffer at the standard rate
        flush=False: write the remainder of the buffer with no delay
        TODO: doc
        """

        with self._lock:
            self._end_thread.set()
            self._end_main_loop.set()

            if any(isinstance(p, RTPPacket) for p in self._buffer) or True:
                if kwargs.pop('flush', False):
                    self._finalizing = True
                    self.DELAY = 0
                elif not kwargs.pop('drain', True):
                    with self._lock:
                        self._finalizing = True
                        self._buffer.clear()

    def reset(self):
        with self._lock:
            self._decoder = Decoder() # TODO: Add a reset function to Decoder itself
            self._last_seq = self._last_ts = 0
            self._buffer.clear()
            self._primed.clear()
            self._end_main_loop.set() # XXX: racy with _push?
            self.DELAY = self.__class__.DELAY

    def _push(self, item):
        if not isinstance(item, (RTPPacket, SilencePacket)):
            raise TypeError(f"item should be an RTPPacket, not {item.__class__.__name__}")

        # XXX: racy with reset?
        if self._end_main_loop.is_set() and not self._end_thread.is_set():
            self._end_main_loop.clear()

        if not self._primed.is_set():
            self._primed.set()

        # Fake packet loss
        # import random
        # if random.randint(1, 100) <= 10 and isinstance(item, RTPPacket):
        #     return

        with self._lock:
            existing_packet = utils.get(self._buffer, timestamp=item.timestamp)
            if isinstance(existing_packet, SilencePacket):
                # Replace silence packets with rtp packets
                self._buffer[self._buffer.index(existing_packet)] = item
                return
            elif isinstance(existing_packet, RTPPacket):
                return # duplicate packet

            bisect.insort(self._buffer, item)

        # Optional diagnostics, will probably remove later
            bufsize = len(self._buffer) # indent intentional
        if bufsize >= self.buffer_size * self._overflow_mult:
            print(f"[router:push] Warning: rtp heap size has grown to {bufsize}")
            self._overflow_mult += self._overflow_incr

        elif bufsize <= self.buffer_size * (self._overflow_mult - self._overflow_incr) \
            and self._overflow_mult > self._overflow_base:

            print(f"[router:push] Info: rtp heap size has shrunk to {bufsize}")
            self._overflow_mult = max(self._overflow_base, self._overflow_mult - self._overflow_incr)

    def _pop(self):
        packet = nextpacket = None
        with self._lock:
            try:
                if not self._finalizing:
                    self._buffer.append(SilencePacket(self.ssrc, self._buffer[-1].timestamp + Decoder.SAMPLES_PER_FRAME))
                packet = self._buffer.pop(0)
                nextpacket = self._buffer[0]
            except IndexError:
                pass # empty buffer

        return packet, nextpacket

    def _initial_fill(self):
        """Artisanal hand-crafted function for buffering packets and clearing discord's stupid fucking rtp buffer."""

        if self._end_main_loop.is_set():
            return

        # Very small sleep to check if there's buffered packets
        time.sleep(0.001)
        if len(self._buffer) > 3:
            # looks like there's some old packets in the buffer
            # we need to figure out where the old packets stop and where the fresh ones begin
            # for that we need to see when we return to the normal packet accumulation rate

            last_size = len(self._buffer)

            # wait until we have the correct rate of packet ingress
            while len(self._buffer) - last_size > 1:
                last_size = len(self._buffer)
                time.sleep(0.001)

            # collect some fresh packets
            time.sleep(0.06)

            # generate list of differences between packet sequences
            with self._lock:
                diffs = [self._buffer[i+1].sequence-self._buffer[i].sequence for i in range(len(self._buffer)-1)]
            sdiffs = sorted(diffs, reverse=True)

            # decide if there's a jump
            jump1, jump2 = sdiffs[:2]
            if jump1 > jump2 * 3:
                # remove the stale packets and keep the fresh ones
                self.truncate(size=len(self._buffer[diffs.index(jump1)+1:]))
            else:
                # otherwise they're all stale, dump 'em (does this ever happen?)
                with self._lock:
                    self._buffer.clear()

        # fill buffer to at least half full
        while len(self._buffer) < self.buffer_size // 2:
            time.sleep(0.001)

        # fill the buffer with silence aligned with the first packet
        # if an rtp packet already exists for the given silence packet ts, the silence packet is ignored
        with self._lock:
            start_ts = self._buffer[0].timestamp
            for x in range(1, 1 + self.buffer_size - len(self._buffer)):
                self._push(SilencePacket(self.ssrc, start_ts + x * Decoder.SAMPLES_PER_FRAME))

        # now fill the rest
        while len(self._buffer) < self.buffer_size:
            time.sleep(0.001)
            # TODO: Maybe only wait at most for about as long we we're supposed to?
            #       0.02 * (buffersize - len(buffer))

    def _packet_gen(self):
        while True:
            packet, nextpacket = self._pop()
            self._last_ts = getattr(packet, 'timestamp', self._last_ts + Decoder.SAMPLES_PER_FRAME)
            self._last_seq += 1 # self._last_seq = packet.sequence?

            if isinstance(packet, RTPPacket):
                pcm = self._decoder.decode(packet.decrypted_data)

            elif isinstance(nextpacket, RTPPacket):
                pcm = self._decoder.decode(packet.decrypted_data, fec=True)
                fec_packet = FECPacket(self.ssrc, nextpacket.sequence - 1, nextpacket.timestamp - Decoder.SAMPLES_PER_FRAME)
                yield fec_packet, pcm

                packet, _ = self._pop()
                self._last_ts += Decoder.SAMPLES_PER_FRAME
                self._last_seq += 1

                pcm = self._decoder.decode(packet.decrypted_data)

            elif packet is None:
                self._finalizing = False
                break
            else:
                pcm = self._decoder.decode(None)

            yield packet, pcm

    def _do_run(self):
        self._primed.wait()
        self._initial_fill()

        self._loops = 0
        packet_gen = self._packet_gen()
        start_time = time.perf_counter()
        try:
            while not self._end_main_loop.is_set() or self._finalizing:
                packet, pcm = next(packet_gen)
                try:
                    self.output_func(pcm, packet.decrypted_data, packet)
                except:
                    log.exception("Sink raised exception")
                    traceback.print_exc()

                next_time = start_time + self.DELAY * self._loops
                self._loops += 1

                time.sleep(max(0, self.DELAY + (next_time - time.perf_counter())))
        except StopIteration:
            time.sleep(0.001) # just in case, so we don't slam the cpu
        finally:
            packet_gen.close()

    def run(self):
        try:
            while not self._end_thread.is_set():
                self._do_run()
        except Exception as e:
            log.exception("Error in decoder %s", self.name)
            traceback.print_exc()

class FuckDecoder:
    def __init__(self,ssrc,cb):
        self.o=1
        self.curbyte=0
        self.data=b''
        self.ssrc=ssrc
        self.cb = cb
        self.bar = None

    def reset(self):
        pass #fuck off

    def stop(self):
        pass #eat shit

    def feed_rtp(self,p):
        print(p)
        try:
            curpack = p.sequence.to_bytes(2,byteorder="big")
            curpack += p.timestamp.to_bytes(4,byteorder="big")[1:]

            from binascii import crc32
            for x in curpack:
                print(self.data)
                self.data += bytes([x])
                if self.data[-4:] == crc32(self.data[:-4]).to_bytes(4,byteorder="little"):
                    print(f"data! {self.data[:-4]}")
                    self.cb(self.data[:-4],self.data[:-4],p)
                    self.data=b''
                    return
        except Exception as e:
            print(e)

    def feed_rtcp(self,p):
        # print(p)
        return
        pass #fuck your ass

class AudioReader(threading.Thread):
    def __init__(self, sink, client, *, after=None):
        super().__init__(daemon=True)
        self.sink = sink
        self.client = client
        self.after = after

        if after is not None and not callable(after):
            raise TypeError('Expected a callable for the "after" parameter.')

        self._box = nacl.secret.SecretBox(bytes(client.secret_key))
        self._decrypt_rtp = getattr(self, '_decrypt_rtp_' + client.mode)
        self._decrypt_rtcp = getattr(self, '_decrypt_rtcp_' + client.mode)

        self._connected = client._connected
        self._current_error = None
        self._buffers = Defaultdict(lambda ssrc: FuckDecoder(ssrc, self._write_to_sink))

        self._end = threading.Event()
        self._decoder_lock = threading.Lock()

    def _decrypt_rtp_xsalsa20_poly1305(self, packet):
        nonce = bytearray(24)
        nonce[:12] = packet.header
        result = self._box.decrypt(bytes(packet.data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305(self, data):
        nonce = bytearray(24)
        nonce[:8] = data[:8]
        result = self._box.decrypt(data[8:], bytes(nonce))

        return data[:8] + result

    def _decrypt_rtp_xsalsa20_poly1305_suffix(self, packet):
        nonce = packet.data[-24:]
        voice_data = packet.data[:-24]
        result = self._box.decrypt(bytes(voice_data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305_suffix(self, data):
        nonce = data[-24:]
        header = data[:8]
        result = self._box.decrypt(data[8:-24], nonce)

        return header + result

    def _decrypt_rtp_xsalsa20_poly1305_lite(self, packet):
        nonce = bytearray(24)
        nonce[:4] = packet.data[-4:]
        voice_data = packet.data[:-4]
        result = self._box.decrypt(bytes(voice_data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305_lite(self, data):
        nonce = bytearray(24)
        nonce[:4] = data[-4:]
        header = data[:8]
        result = self._box.decrypt(data[8:-4], bytes(nonce))

        return header + result

    def _reset_decoders(self, *ssrcs):
        with self._decoder_lock:
            if not ssrcs:
                for decoder in self._buffers.values():
                    decoder.reset()
            else:
                for ssrc in ssrcs:
                    d = self._buffers.get(ssrc)
                    if d:
                        d.reset()

    def _stop_decoders(self, *ssrcs, **kwargs):
        with self._decoder_lock:
            if not ssrcs:
                for decoder in self._buffers.values():
                    decoder.stop(**kwargs)
            else:
                for ssrc in ssrcs:
                    decoder = self._buffers.get(ssrc)
                    if decoder:
                        decoder.stop(**kwargs)

    def _ssrc_removed(self, ssrc):
        # An user has disconnected but there still may be
        # packets from them left in the buffer to read
        # For now we're just going to kill the decoder and see how that works out
        # I *think* this is the correct way to do this
        # Depending on how many leftovers I end up with I may reconsider

        with self._decoder_lock:
            decoder = self._buffers.pop(ssrc, None)

            if decoder is None:
                print(f"!!! No decoder for ssrc {ssrc} was found?")
            else:
                decoder.stop()
                # if decoder._buffer:
                    # print(f"Decoder had {len(decoder._buffer)} packets remaining")

    def _get_user(self, packet):
        user_id = self.client._ssrcs.get(packet.ssrc)
        return self.client.guild.get_member(user_id)

    def _write_to_sink(self, pcm, opus, packet):
        try:
            # print("!!!")
            data = opus if self.sink.wants_opus() else pcm
            user = self._get_user(packet)
            self.sink.write(VoiceData(data, user, packet))
        except SinkExit as e:
            log.info("Shutting down reader thread %s", self)
            self.stop()
            self._stop_decoders(**e.kwargs)
        except:
            traceback.print_exc()
            # insert optional error handling here

    def _set_sink(self, sink):
        with self._decoder_lock:
            self.sink = sink
        # if i were to fire a sink change mini-event it would be here

    def _do_run(self):
        while not self._end.is_set():
            if not self._connected.is_set():
                self._connected.wait()

            ready, _, err = select.select([self.client.socket], [],
                                          [self.client.socket], 0.01)
            
            if not ready:
                if err:
                    print("Socket error")
                continue

            try:
                raw_data = self.client.socket.recv(4096)
            except socket.error as e:
                t0 = time.time()

                if e.errno == 10038: # ENOTSOCK
                    continue

                log.exception("Socket error in reader thread ")
                print(f"Socket error in reader thread: {e} {t0}")

                with self.client._connecting:
                    timed_out = self.client._connecting.wait(20)

                if not timed_out:
                    raise
                elif self.client.is_connected():
                    print(f"Reconnected in {time.time()-t0:.4f}s")
                    continue
                else:
                    raise

            try:
                packet = None
                log.debug(f"Received packet of length {len(raw_data)}")
                if not is_rtcp(raw_data):
                    packet = decode(raw_data)
                    packet.decrypted_data = self._decrypt_rtp(packet)
                else:
                    packet = decode(self._decrypt_rtcp(raw_data))
                    if not isinstance(packet, ReceiverReportPacket):
                        pass
                        # print(packet)

                        # TODO: Fabricate and send SenderReports and see what happens

                    for buff in list(self._buffers.values()):
                        buff.feed_rtcp(packet)

                    continue

            except CryptoError:
                log.exception("CryptoError decoding packet %s", packet)
                continue

            except:
                log.exception("Error unpacking packet")
                traceback.print_exc()

            else:
                log.debug("%s", packet)
                if packet.ssrc not in self.client._ssrcs:
                    log.debug("Received packet for unknown ssrc %s", packet.ssrc)

                self._buffers[packet.ssrc].feed_rtp(packet)

    def stop(self):
        self._end.set()

    def run(self):
        try:
            self._do_run()
        except socket.error as exc:
            self._current_error = exc
            self.stop()
        except Exception as exc:
            traceback.print_exc()
            self._current_error = exc
            self.stop()
        finally:
            self._stop_decoders()
            try:
                self.sink.cleanup()
            except:
                log.exception("Error during sink cleanup")
                # Testing only
                traceback.print_exc()

            self._call_after()

    def _call_after(self):
         if self.after is not None:
            try:
                self.after(self._current_error)
            except Exception:
                log.exception('Calling the after function failed.')

    def is_listening(self):
        return not self._end.is_set()