# Schnoz - Common Lisp packet sniffer and inspection

Lispy network processing.

requires postgreSQL; [postmodern](https://github.com/marijnh/Postmodern), flexi-streams, bit-smasher, [cl-cidr-notation](https://github.com/AccelerationNet/cl-cidr-notation), symbol-munger, alexandria, ipcalc-lisp, cl-ppcre, ipand [plokami](https://github.com/atomontage/plokami) are available on quicklisp

# Install

build an SBCL image with dependencies and run
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
(latest-batch! 5) ;; last 5 packets ->

"Batch process startup at : 3693092398"
(272883577289159 198414855633894 IPV6 (8198 57 8764690268168 13194139533312)) 

(272883577289159 198414855633894 IPV6 (17926 57 8764690268168 13194139533312)) 

(198414855633894 272883577289159 IPV6 (8198 64 1111423516702 234456553719863)) 

(272883577289159 198414855633894 IPV6 (8198 57 8764690268168 13194139533312)) 

(272883577289159 198414855633894 IPV4 (4 40 39250 6 58.75.35.205 192.168.1.249)) 

"SQL record query done at : 3693092398"
"Batch process done at : 3693092398"

```'