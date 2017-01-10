;; Common Lisp network analysis toolkit
;; TD: 
;; output silent
;; capture for time
;; IP identity association relations
;; sql records (by source/dest/port) -> borealis display 
;; statistical packet analysis
;; ^ (chart of measures on packets from test sessions <sitereq> -> net <-
;; ^ (kommissar reqs)

(defun db-connect ()
  (postmodern:connect-toplevel
 "schnoz" "postgres" "URA!URA!URA!" "localhost")
  (format 'nil "Database connected."))
(defun db-restart ()
  (postmodern:disconnect-toplevel)
  (db-connect))
(defun db-init-tables ()
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
(defun psql-q (query-seq)  
  (postmodern:query (join-str query-seq " ")))
(defun insert (table values)  
  (psql-q (list
   "insert into " 
   table " values (" 
   (join-str values ",") ")"))
)

(defun capture-handler (sec usec caplen len buffer)
  ;;  (format t "Packet length: ~A bytes,: ~A bytes~%" caplen buffer)
  ;; (map 'string #'code-char buffer)
  "~"
  ;; (print buffer) ;; -> #(249 38 38 38) -> stdio
  (setq buf-str (print buffer))
  "~"
  ;; DEVICE ?
  (psql-q (list "insert into packet (buffer,length,stamp) values ("
		"'" buf-str "',"
		(format nil "~a" len) ","
		"(select CURRENT_TIMESTAMP))")))

(defun capture-to-db (device-name &optional time)
  ;; (clock)
  (plokami:with-pcap-interface 
      (plokami::pcap device-name 
		     :promisc t 
		     :snaplen 1500 
		     :nbio t)
    (plokami:set-filter plokami::pcap "ip")
    (loop
       (plokami:capture plokami::pcap -1 
			(lambda (sec usec caplen len buffer)
			  (capture-handler sec usec caplen len buffer)))
       (sleep 0.01)))
  )
(defun capture-for-time (device-name time-secs)
  (capture-to-db time-secs))

(defun capture-wlan0 () (capture-to-db "wlan0"))
(defun capture-eth0 () (capture-to-db "eth0"))

(defun delete-before (date) (psql-q '()))
(defun select-by-identity (identity) 
  (psql-q '()))

