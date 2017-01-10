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

(setq ip-header-fields '(
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
(defun bytes-to-string (byte-list)
  (flexi-streams:octets-to-string byte-list :external-format :utf-8))

(defun read-header (byte-list)

  (defun read-byte ()
    (flexi-streams:peek-byte stream))
  (setq stream (flexi-streams:make-flexi-stream
	     (flexi-streams:make-in-memory-input-stream
	      byte-list))    
   first-octet  (read-byte)

   version      (ldb (byte 4 4) first-octet)
   ihl          (ldb (byte 0 4) first-octet) ;; internet header length
   tos          (peek-byte stream)
   length       (octet->u16 (read-byte) (read-byte))
   id           (octet->u16 (read-byte) (read-byte))
   flags-n-offset       (octet->u16 (read-byte) (read-byte))
   ttl          (peek-byte stream)
   protocol     (peek-byte stream) ;; see prtcol #s
   checksum     (octet->u16 (read-byte) (read-byte))
   saddr        (octet->u32 (read-byte) (read-byte)
			    (read-byte) (read-byte))
   daddr        (octet->u32 (read-byte) (read-byte)
			    (read-byte) (read-byte)))

  (list version ihl tos length id offset ttl protocol checksum saddr daddr))

(defun num-to-ip (num)
  (cl-cidr-notation:cidr-string num))
(defun ip-to-num (ip-string)
  (cl-cidr-notation:parse-cidr ip-string))

(defun records-between (table begin-id end-id)
  (psql-q (list (c+ "select * from " table " where id > "
	      (write-to-string begin-id) " and id < " (write-to-string 
						       end-id) )))
  (profile-s "SQL record query done") 
)
(defun profile-s (process-desc)
  (format t "~% ~a at : ~a" process-desc (get-universal-time)))

(defun process-packets! (packet-list)
  (loop for i in packet-list       
       do (print i)

       ;; (read-to-header i)       
       )
  )

(defun process-batch! (begin-id end-id)
  (profile-s "Batch process startup")
  
  (setq packet-list 
     (records-between "packet" begin-id end-id))  
  
  (process-packets! packet-list)

  (profile-s "Batch process done")    
)

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

