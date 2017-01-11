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
(latest-batch! 3) ;; read last 3 packets from db ->

"Batch process startup at : 3693092398"

(dest-mac: 272883577289159 src-mac: 198414855633894 ether-type: IPV6 86 dd
 (ver: 6 len: 1358 traf class: 0 flow class: (00 00 00) next-header: 17 addrs:
  2607:f8b0:401a:0026:0000:0000:0000:000c
  2601:02c6:0100:1ed5:a5c4:9f50:7cb3:b234)) 

(dest-mac: 272883577289159 src-mac: 198414855633894 ether-type: IPV6 86 dd
 (ver: 6 len: 1358 traf class: 0 flow class: (00 00 00) next-header: 17 addrs:
  2607:f8b0:401a:0026:0000:0000:0000:000c
  2601:02c6:0100:1ed5:a5c4:9f50:7cb3:b234)) 

(dest-mac: 272883577289159 src-mac: 198414855633894 ether-type: IPV6 86 dd
 (ver: 6 len: 1358 traf class: 0 flow class: (00 00 00) next-header: 17 addrs:
  2607:f8b0:401a:0026:0000:0000:0000:000c
  2601:02c6:0100:1ed5:a5c4:9f50:7cb3:b234)) 

"SQL record query done at : 3693092398"
"Batch process done at : 3693092398"

```

# Development

tools such as wireshark can be used to develop packet formats and data byte by byte
for schnoz datagram parsing and network capabilities

use bitwise functions such as 'concat-bits or 'octet->u16 from schnoz.lisp to distribute and pack bit values from packet buffers

SQL records in database are compatible with other statistical analysis platforms such as R or any capable of connecting to the sql server

