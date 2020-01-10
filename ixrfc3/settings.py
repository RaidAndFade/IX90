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


# Patch3 is exclusively on #beep. not on #weird-beeps like previous versions
ispchan= 

# This can be left None unless you have been allocated a static IP address.
addr=''
netmask=''

# This must be set to the value allocated to you by your ISP. Ask RAID for your MAC ADDRESS.
macaddr=b'ur mac here'

# These are settings that you have control over. 
#  tkn is the token of the bot you plan on connecting with
#  ifup and ifdown will be run POST-UP and POST-DOWN. ifdown will not be run on a force-quit
#  iface is the name of the vpn interface. the default is dscd and most tutorials will use dscd.

# Tokens here
tkn = ['']
ifup="" 
ifdown=""
iface="dscd"

# These two should only be changed by the net-admin
mtu=1475
debug=True
