# Schnoz - Common Lisp packet sniffer and inspection

Lispy network processing.

requires postgreSQL; [postmodern](https://github.com/marijnh/Postmodern), flexi-streams, bit-smasher, [cl-cidr-notation](https://github.com/AccelerationNet/cl-cidr-notation), symbol-munger, alexandria, ipcalc-lisp, cl-ppcre, and [plokami](https://github.com/atomontage/plokami) are available on quicklisp

# Install

install and start a postgresql server, build an SBCL image with dependencies and run
```sh
sh run.sh
```

connect to the database and capture traffic
```lisp
(db-connect)
(capture-wlan0! 20) ;; for 20 seconds ->

"43 packets received, 0 dropped"
```

process packet contents
```lisp
(latest-batch! 4) ;; read last 4 packets from db ->

"Batch process startup at : 3693092398"

((dest-mac: f8:2f:a8:b0:79:c7 src-mac: b4:75:0e:fc:fb:e6 ether-type: IPV4 08 00
  (4 52 54544 6 50.18.192.251 192.168.1.249))
 db store time: 3693126819) 

((dest-mac: b4:75:0e:fc:fb:e6 src-mac: f8:2f:a8:b0:79:c7 ether-type: IPV4 08 00
  (4 52 64935 6 192.168.1.249 50.18.192.251))
 db store time: 3693126820) 

((dest-mac: f8:2f:a8:b0:79:c7 src-mac: b4:75:0e:fc:fb:e6 ether-type: IPV6 86 dd
  (ver: 6 len: 32 traf class: 0 flow class: (00 00 00) next-header: 6 addrs:
   2607:f8b0:4000:080c:0000:0000:0000:2005
   2601:02c6:0100:1ed5:a5c4:9f50:7cb3:b234))
 db store time: 3693126822) 

((dest-mac: f8:2f:a8:b0:79:c7 src-mac: b4:75:0e:fc:fb:e6 ether-type: ARP 08 06
  NIL)
 db store time: 3693126823) 


"SQL record query done at : 3693092398"
"Batch process done at : 3693092398"

```

# Development

use bitwise functions such as 'hex, 'concat-bits or 'octet->u16 from schnoz.lisp to distribute and pack bit values from packet buffers and adress representations

SQL records in database are compatible with other statistical analysis platforms such as R or any capable of connecting to the sql server

tools such as wireshark can be used to develop packet formats and data byte by byte
for schnoz datagram parsing and network capabilities

