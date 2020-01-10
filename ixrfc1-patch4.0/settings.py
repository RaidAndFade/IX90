tkns=[ # list of bot tokens (will use all of them so make sure all can access ispchan)
    "tkn1",
    "tkn2"
]
ispchan=1 # id of the discord channel  used as transit
addr=None # static address for this iface (dhcp leave this as None)
macaddr=b'\x66\x69\x90\xYY\xYY\xYY' # mac address for this iface 
netmask=None # netmask for the static address (leave this blank if dhcp)
mtu=1475 
debug=False # debug messages , much more verbose
ifup="" # command to run when iface come up
ifdown="" # command to run when iface go down
iface="dscd" # name of TAP iface
