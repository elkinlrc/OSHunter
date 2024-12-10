lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
        inet 127.0.0.1 netmask 0xff000000
        inet6 ::1 prefixlen 128 
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
        nd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
stf0: flags=0<> mtu 1280
anpi1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 4e:7c:cb:64:22:1d
        media: none
        status: inactive
anpi0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 4e:7c:cb:64:22:1c
        media: none
        status: inactive
en3: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 4e:7c:cb:64:22:fc
        nd6 options=201<PERFORMNUD,DAD>
        media: none
        status: inactive
en4: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 4e:7c:cb:64:22:fd
        nd6 options=201<PERFORMNUD,DAD>
        media: none
        status: inactive
en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        options=460<TSO4,TSO6,CHANNEL_IO>
        ether 36:c3:4f:6d:3d:40
        media: autoselect <full-duplex>
        status: inactive
en2: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        options=460<TSO4,TSO6,CHANNEL_IO>
        ether 36:c3:4f:6d:3d:44
        media: autoselect <full-duplex>
        status: inactive
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=63<RXCSUM,TXCSUM,TSO4,TSO6>
        ether 36:c3:4f:6d:3d:40
        Configuration:
                id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
                maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
                root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
                ipfilter disabled flags 0x0
        member: en1 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 8 priority 0 path cost 0
        member: en2 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 9 priority 0 path cost 0
        nd6 options=201<PERFORMNUD,DAD>
        media: <unknown type>
        status: inactive
ap1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
        ether 4a:8f:37:0e:74:ec
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect (none)
        status: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
        ether 16:55:fe:26:47:31
        inet6 fe80::414:97c:c0c:fd93%en0 prefixlen 64 secured scopeid 0xb 
        inet 192.168.1.139 netmask 0xffffff00 broadcast 192.168.1.255
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::995d:1d1a:72e8:e1e8%utun0 prefixlen 64 scopeid 0xd 
        nd6 options=201<PERFORMNUD,DAD>
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        inet6 fe80::924e:7555:47cb:6a5e%utun1 prefixlen 64 scopeid 0xe 
        nd6 options=201<PERFORMNUD,DAD>
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1000
        inet6 fe80::ce81:b1c:bd2c:69e%utun2 prefixlen 64 scopeid 0xf 
        nd6 options=201<PERFORMNUD,DAD>
awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
        ether 26:9e:3e:97:37:35
        inet6 fe80::249e:3eff:fe97:3735%awdl0 prefixlen 64 scopeid 0x10 
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
llw0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 26:9e:3e:97:37:35
        inet6 fe80::249e:3eff:fe97:3735%llw0 prefixlen 64 scopeid 0x11 
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect (none)
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
        inet6 fe80::e902:a39c:27f5:1b78%utun3 prefixlen 64 scopeid 0x12 
        nd6 options=201<PERFORMNUD,DAD>
vmenet0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        ether 6e:95:c6:86:5e:48
        media: autoselect
        status: active
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=3<RXCSUM,TXCSUM>
        ether ae:c9:06:42:28:64
        inet6 fe80::acc9:6ff:fe42:2864%bridge100 prefixlen 64 scopeid 0x14 
        inet 172.16.214.1 netmask 0xffff0000 broadcast 172.16.255.255
        Configuration:
                id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
                maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
                root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
                ipfilter disabled flags 0x0
        member: vmenet0 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 19 priority 0 path cost 0
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
vmenet1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        ether 92:2a:5b:e6:93:af
        media: autoselect
        status: active
bridge101: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=3<RXCSUM,TXCSUM>
        ether ae:c9:06:42:28:65
        inet 192.168.250.1 netmask 0xffffff00 broadcast 192.168.250.255
        inet6 fe80::acc9:6ff:fe42:2865%bridge101 prefixlen 64 scopeid 0x16 
        Configuration:
                id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
                maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
                root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
                ipfilter disabled flags 0x0
        member: vmenet1 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 21 priority 0 path cost 0
        member: vmenet2 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 23 priority 0 path cost 0
        member: vmenet3 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 24 priority 0 path cost 0
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
vmenet2: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        ether fe:a3:73:7a:52:b9
        media: autoselect
        status: active
vmenet3: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
        ether 56:ca:61:4d:35:e2
        media: autoselect
        status: active
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::3ccb:2141:fe00:2bcd%utun4 prefixlen 64 scopeid 0x19 
        nd6 options=201<PERFORMNUD,DAD>
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::72cd:6cb4:9491:b33a%utun5 prefixlen 64 scopeid 0x1a 
        nd6 options=201<PERFORMNUD,DAD>
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
        inet6 fe80::871d:85f6:807:3ea6%utun6 prefixlen 64 scopeid 0x1b 
        nd6 options=201<PERFORMNUD,DAD>
utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::7742:a6b1:5ea6:52b7%utun7 prefixlen 64 scopeid 0x1c 
        nd6 options=201<PERFORMNUD,DAD>
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        inet6 fe80::522b:e873:9f32:74dd%utun8 prefixlen 64 scopeid 0x1d 
        nd6 options=201<PERFORMNUD,DAD>
utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1000
        inet6 fe80::ce81:b1c:bd2c:69e%utun9 prefixlen 64 scopeid 0x1e 
        nd6 options=201<PERFORMNUD,DAD>
utun10: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::e9e2:e6e8:4390:4785%utun10 prefixlen 64 scopeid 0x1f 
        nd6 options=201<PERFORMNUD,DAD>
utun11: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::b63a:5e47:57c7:c579%utun11 prefixlen 64 scopeid 0x20 
        nd6 options=201<PERFORMNUD,DAD>
utun12: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::9af3:463:18ed:a5e0%utun12 prefixlen 64 scopeid 0x21 
        nd6 options=201<PERFORMNUD,DAD>
utun13: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet6 fe80::a935:366:9dbc:928%utun13 prefixlen 64 scopeid 0x22 
        nd6 options=201<PERFORMNUD,DAD>