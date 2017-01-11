# Schnoz - Common Lisp packet sniffer and inspection

Lispy network processing.

requires postgreSQL; [postmodern](https://github.com/marijnh/Postmodern), flexi-streams, bit-smasher, [cl-cidr-notation](https://github.com/AccelerationNet/cl-cidr-notation), symbol-munger, and [plokami](https://github.com/atomontage/plokami) are available on quicklisp

# Install

build an SBCL image with dependencies and run
```sh
sh run.sh
```

connect to the database and capture traffic
```lisp
(db-connect)
(capture-wlan0! 20) ;; for 20 seconds
```

process packet contents
```lisp
(latest-batch! 5) ;; last 5 packets
```