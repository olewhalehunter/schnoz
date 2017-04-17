# Schnoz - Common Lisp packet sniffer and inspection

Lispy network processing.

requires postgreSQL; [postmodern](https://github.com/marijnh/Postmodern), flexi-streams, bit-smasher, [cl-cidr-notation](https://github.com/AccelerationNet/cl-cidr-notation), symbol-munger, alexandria, ipcalc-lisp, drakma, cl-ppcre, and [plokami](https://github.com/atomontage/plokami) are available on quicklisp

# Install

install and start a postgresql server, update strings in config.lisp, then build an SBCL image with the dependencies above and execute run.sh

connect to the database and capture traffic
```lisp
(db-connect)
(capture-wlan0! 20) ;; for 20 seconds ->

"43 packets received, 0 dropped"
```

process packet contents
```lisp
(latest-batch! 1) ;; read last 1 packets from db ->

 Batch process startup at : 3693157001
((dest-mac: f8:2f:a8:b0:79:c7 src-mac: b4:75:0e:fc:fb:e6 ether-type: IPV6 86 dd
  (ver: 6 len: 101 traf class: 0 flow class: (00 00 00) next-header: 17 addrs:
   2607:f8b0:401a:0001:0000:0000:0000:0008
   2601:02c6:0100:1ed5:a5c4:9f50:7cb3:b234))
 db store time: 3693134367) 
Source addr already registered
Destination addr already registered

 SQL record query done at : 3693157001
 Batch process done at : 3693157001

```

# Development

SQL records in database are compatible with other statistical analysis platforms such as R or any capable of connecting to the SQL server.


# To Do

* ident db register script gen (alter desc)
* blacklist prescription list -> sh
* network mapping
* live capture configuration options
* daily interval sniff scheduler
* isolation testing
* statistical packet analysis
* session report generation