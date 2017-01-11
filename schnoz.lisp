;; Common Lisp network analysis toolkit
;;
;; td : 
;; header process -> db tables
;; IP/ident/src/dest/protoc assoc relations
;; source switching (isolation test)
;; statistical packet analysis -> borealis
;; chart of measures on packets by session target
;; kommissar builtin reqs
;; device sql tables
;; content process profile, async
;; category lisp, better orm, clean
;; ipv6 vs ipv4 packets, all on 6 rn

(load "~/projects/schnoz//cl-cidr-notation/src/packages.lisp")
(load "~/projects/schnoz//cl-cidr-notation/src/cl-cidr-notation.lisp")

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
    (plokami:set-filter plokami::pcap "ip")

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
  
(defun capture-wlan0! (seconds)
  (handler-case (progn (format 
			t (concatenate 'string
				       "~%~%"
				       " " rr "|~%~%"))
		       (finish-output nil))
    (error (condition)))
  (capture-to-db! "wlan0" seconds))
(defun capture-eth0! (seconds)
  (capture-to-db! "eth0" seconds))


(defun delete-before-id (id)
  (psql-q '("delete from packet where id < " id)))

(setq ipv4-header-fields '(
			(ver-ihl  :uint8) ;; 4 bits format + 4 bits length
			(tos      :uint8) ;; type of service
			(length   :uint16) ;; total length in octets
			(id       :uint16) ;; sender val
			(offset   :uint16) ;; where in datagram belongs
			(ttl      :uint8)  ;; time to live
			(protocol :uint8)  ;; protocol (see assinged nums)
			(checksum :uint16) ;; header checksum
			(saddr    :uint32) ;; source addr
			(daddr    :uint32) ;; destination addr
			'options            ;; security stuff,route info,see doc
			'datagram-content
			))
(setq ipv6-header-field '(
		       (version        4bits) ;; 0110
		       (traffic-class  :uint8)		       
		       (flow-label     20bits)
		       (Payload-length :uint16)
		       (next-header    :uint8) ;; same as ipv4 protocol #
		       (hop-limit      :uint8)
		       (source-addr    128bits)
		       (dest-addr      128bits)
))

(defun concat-bits (&rest vectors)
  (reduce (lambda (a b) (concatenate
		    'vector
		    (if (typep a 'sequence) a (list a))
		    (if (typep b 'sequence) b (list b))))
          vectors))
(defun list-to-bits (my-list)
  (make-array (length my-list) :initial-contents my-list :element-type 'bit))
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

(defun in-byte () (read-byte stream))

(defun read-ipv4-header (byte-list) 

  (setq stream (flexi-streams:make-flexi-stream
	     (flexi-streams:make-in-memory-input-stream
	      byte-list))

   first-octet  (in-byte)

   version      (ldb (byte 0 4) first-octet)
   ihl          (ldb (byte 4 4) first-octet)
   tos          (in-byte)
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

  (list version ihl tos length id flags-n-offset 
	ttl protocol checksum saddr daddr))
(defun read-ipv6-header (byte-list) 

  (setq stream (flexi-streams:make-flexi-stream
	     (flexi-streams:make-in-memory-input-stream
	      byte-list))

   first-octet  (in-byte)

   version      (ldb (byte 0 4) first-octet) 
   traf-class1  (ldb (byte 4 4) first-octet) 
   second-octet (in-byte)                    

   traf-class2 (ldb (byte 0 4) second-octet) 
   flow-label1 (ldb (byte 4 4) second-octet) 

   flow-label2 (octet->u16 (in-byte) (in-byte)) 
   length      (octet->u16 (in-byte) (in-byte))
   next-header (in-byte)
   hop-limit   (in-byte)   
   saddr        (octet->u128 (in-byte) (in-byte)
			    (in-byte) (in-byte)
			    (in-byte) (in-byte))
   daddr        (octet->u128 (in-byte) (in-byte)
			    (in-byte) (in-byte)
			    (in-byte) (in-byte)))

  (list version length next-header saddr daddr))
(defun read-ethernet-frame (byte-list)
)

(defun process-packet-buf! (buf-list)
  (setq byte-list (read-from-string (elt buf-list 0)))

  (setq metadata (read-ipv6-header byte-list))
  (print buf-list)
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
  (format 
   t (concatenate 'string
		  "~%~%"
		  " " rr "|~%~%"))
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

