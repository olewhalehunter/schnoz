;; Common Lisp network analysis toolkit
;;
;; td : 
;; mac addr translate
;; ip db register 
;; packet metadata db register
;; ident db register
;; network map
;; source switching (isolation test)
;; ip firewall from lisp
;; statistical packet analysis -> borealis
;; chart of measures on packets by session target
;; kommissar builtin reqs
;; device sql tables
;; content process profile, async
;; category lisp, better orm, clean
;; ipv6 vs ipv4 packets, all on 6 rn

(defun load-reqs ()
  (load "~/projects/schnoz//cl-cidr-notation/src/packages.lisp")
  (load "~/projects/schnoz//cl-cidr-notation/src/cl-cidr-notation.lisp")
) (load-reqs)
(defun available-devices ()
  (plokami:find-all-devs))
(defun db-connect ()
  (postmodern:connect-toplevel
 "schnoz" "postgres" "URA!URA!URA!" "localhost")
  (format 'nil "Database connected."))
(defun db-restart ()
  (postmodern:disconnect-toplevel)
  (db-connect))
(defun db-init-tables! ()
  (psql-q   '("create table packet ("
	      "id SERIAL, "
	      "buffer TEXT,"
	      "length BIGINT,"
	      "stamp TIMESTAMP without time zone)"))
  (psql-q   '("create table ip ("
	      "id SERIAL, "
	      "identity BIGINT,"
	      "addr TEXT)"))
  (psql-q   '("create table identity ("
	      "id SERIAL, "
	      "name TEXT)"))
)

(defun c+ (&rest strings)
  (apply #'concatenate 'string strings))
(defun join-str (seq delim)
  (format nil (c+ "~{~A~^" delim "~}") seq))
(defun q (query)
  (postmodern:query query))
(defun psql-q (query-seq)  
  (q (join-str query-seq " ")))
(defun insert! (table values)  
  (psql-q (list
   "insert into " 
   table " values (" 
   (join-str values ",") ")"))
)

(defun clock-time () 
  (get-universal-time))
(defun store-capture! (sec usec caplen len buffer)
  (psql-q (list "insert into packet (buffer,length,stamp) values ("
		"'" (format nil "~a" buffer) "',"
		(format nil "~a" len) ","
		"(select CURRENT_TIMESTAMP))")))
(defun capture-to-db! (device-name time-seconds)  
  (plokami:with-pcap-interface 
      (plokami::pcap device-name 
		     :promisc t 
		     :snaplen 1500 
		     :nbio t)
    ;; (plokami:set-filter plokami::pcap "ip")

    (setq begin (clock-time))
    (loop do 
	 (plokami:capture plokami::pcap -1 
			  (lambda (sec usec caplen len buffer)
			    
			    (store-capture! sec usec caplen len buffer)
			   ;; (check-ip packet)
			    ))
	 (sleep 0.01)
       until (> (clock-time) (+ begin time-seconds)))
       ))
  

(defun d~ () 
  (handler-case (progn (format 
			t (concatenate 'string
				       "~%~%"
				       "   |" rr "|~%~%"))
		       (finish-output nil))
    (error (condition))))
(defun capture-wlan0! (seconds)
  (d~)
  (capture-to-db! "wlan0" seconds))
(defun capture-eth0! (seconds)
  (capture-to-db! "eth0" seconds))

(defun delete-before-id (id)
  (psql-q '("delete from packet where id < " id)))

(defun concat-bits (&rest vectors)
  (reduce (lambda (a b) (concatenate
		    'vector
		    (if (typep a 'sequence) a (list a))
		    (if (typep b 'sequence) b (list b))))
          vectors))
(defun list-to-bits (my-list)
  (make-array (length my-list) :initial-contents my-list :element-type 'bit))
(defun octet->6bytes (a b c d e f)
  (bit-smasher:int<- 
   (list-to-bits (concat-bits (bit-smasher:bits<- a)
			      (bit-smasher:bits<- b)
			      (bit-smasher:bits<- c)
			      (bit-smasher:bits<- d)
			      (bit-smasher:bits<- e)
			      (bit-smasher:bits<- f)))))
(defun octet->u16 (upper lower)
  (bit-smasher:int<- 
   (list-to-bits (concat-bits (bit-smasher:bits<- upper)
			      (bit-smasher:bits<- lower)))))
(defun octet->u32 (a b c d)
  (bit-smasher:int<- 
   (list-to-bits (concat-bits (bit-smasher:bits<- a)
			      (bit-smasher:bits<- b)
			      (bit-smasher:bits<- c)
			      (bit-smasher:bits<- d)))))
(defun octet->u128 (a b c d e f)
  (bit-smasher:int<- 
   (list-to-bits (concat-bits (bit-smasher:bits<- a)
			      (bit-smasher:bits<- b)
			      (bit-smasher:bits<- c)
			      (bit-smasher:bits<- d)
			      (bit-smasher:bits<- e)
			      (bit-smasher:bits<- f)))))
(defun bytes-to-string (byte-list)
  (flexi-streams:octets-to-string byte-list :external-format :utf-8))
(defun hex-to-int (hex-str) (bit-smasher::int<- hex-str))
(defun ipv6-addr-string (num)

  (c+ (bit-smasher:hex<- (ldb (byte 2 0) num))
      (bit-smasher:hex<- (ldb (byte 2 2) num)) ":"
      (bit-smasher:hex<- (ldb (byte 2 4) num)) 
      (bit-smasher:hex<- (ldb (byte 2 6) num)) ":"
      (bit-smasher:hex<- (ldb (byte 2 8) num)) 
      (bit-smasher:hex<- (ldb (byte 2 10) num)) ":"
      (bit-smasher:hex<- (ldb (byte 2 12) num)) 
      (bit-smasher:hex<- (ldb (byte 2 14) num)) ":"
      (bit-smasher:hex<- (ldb (byte 2 16) num)) 
      (bit-smasher:hex<- (ldb (byte 2 18) num)) ":"
      (bit-smasher:hex<- (ldb (byte 2 20) num)) 
      (bit-smasher:hex<- (ldb (byte 2 22) num))  ":"
      (bit-smasher:hex<- (ldb (byte 2 24) num)) 
      (bit-smasher:hex<- (ldb (byte 2 26) num)) 
      )
)

(defun num-to-ip (num)
  (cl-cidr-notation:cidr-string num))
(defun ip-to-num (ip-string)
  (cl-cidr-notation:parse-cidr ip-string))

(defun records-between (table values begin-id end-id) 
 
   (q (c+ "select " values " from " table " where id > "
	      (write-to-string begin-id) " and id < " (write-to-string 
						       end-id)))
)
(defun profile-s (process-desc)
  (format t "~% ~a at : ~a" process-desc (get-universal-time)))

(defun in-byte () (read-byte frame-stream))

(defun hex (dec)
  (bit-smasher:hex<- dec))

(defun scan-ipv6-text-addr ()
  (c+ (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte)) ":"
      (hex (in-byte)) (hex (in-byte))))
(defun process-ipv6-data (stream) 
  (setq first-byte (in-byte)
     version (ldb (byte 4 4) first-byte)
     traf-class  (ldb (byte 0 4) first-byte) 

     flow-class (list (hex (in-byte)) 
		  (hex (in-byte))
		  (hex (in-byte)))

     length      (octet->u16 (in-byte) (in-byte))
     next-header (in-byte)
     hop-limit   (in-byte)

     saddr        (scan-ipv6-text-addr)
     daddr        (scan-ipv6-text-addr)
     ) 
  (list "ver:" version
	"len:" length
	"traf class:" traf-class
	"flow class:" flow-class
	"next-header:" next-header
	"addrs:" saddr daddr)
)

(defun process-ipv4-data (stream) 
  (setq ver-ihl (in-byte)
     ihl  (ldb (byte 4 4) ver-ihl)
     tos (in-byte)
     length       (octet->u16 (in-byte) (in-byte))
     id           (octet->u16 (in-byte) (in-byte))
     flags-n-offset       (octet->u16 (in-byte) (in-byte))
     ttl          (in-byte)
     protocol     (in-byte) ;; see prtcol #s
     checksum     (octet->u16 (in-byte) (in-byte))
     saddr        (octet->u32 (in-byte) (in-byte)
			      (in-byte) (in-byte))
     daddr        (octet->u32 (in-byte) (in-byte)
			      (in-byte) (in-byte)))   
  (list ihl length id protocol (num-to-ip saddr)
	(num-to-ip daddr))
)


(defun read-ethernet-frame (byte-list)
  (setq frame-stream (flexi-streams:make-flexi-stream
	     (flexi-streams:make-in-memory-input-stream
	      byte-list))

   dest-mac   (octet->6bytes (in-byte) (in-byte) (in-byte)
			     (in-byte) (in-byte) (in-byte))
   src-mac    (octet->6bytes (in-byte) (in-byte) (in-byte)
			     (in-byte) (in-byte) (in-byte))
   oct1 (in-byte) oct2 (in-byte)
   ether-type (let ((val (octet->u16 oct1 oct2)))
		(cond ((and (= oct1 134) (= oct2 221)) 'ipv6)		      
		      ((and (= oct1 8) (= oct2 0)) 'ipv4)
		      ((= val 2054) 'arp))))
     
  (list "dest-mac:" dest-mac
	"src-mac:" src-mac
	"ether-type:" ether-type (hex oct1) (hex oct2)
	(cond ((eq ether-type 'ipv4) (process-ipv4-data frame-stream))
	      ((eq ether-type 'ipv6) (process-ipv6-data frame-stream)))))

(defun process-packet-buf! (buf-list)
  (setq byte-list (read-from-string (elt buf-list 0)))

  (setq metadata (read-ethernet-frame byte-list))

  (format t "~%~a ~%" metadata)
)
(defun process-packets! (packet-list)
  (loop for i in packet-list       
       do (process-packet-buf! i)))

(defun latest-packet-id ()
  (caar (psql-q '("select max(id) from packet"))))
(defun process-batch! (begin-id end-id)
  (profile-s "Batch process startup")
  
  (process-packets! 
   (records-between "packet" "buffer" begin-id end-id))
  (profile-s "SQL record query done") 

  (profile-s "Batch process done")   
  (d~)
)
(defun latest-batch! (n)
  (process-batch! (- (latest-packet-id) (+ n 1)) (latest-packet-id)))

(defun packet-identified? (packet)  
)
(defun packet-identity? (packet)
)
(defun ip-addr-identity? (ip-num)
  (psql-q "select * from where "))
(defun register-packet! ()
)


(defun select-by-identity (identity) 
  (psql-q '("select from packetident where packet = identity")))
(defun delete-before-id (id)
  (psql-q '("delete from packet where id < " id)))

