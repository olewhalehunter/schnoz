;; Common Lisp network analysis toolkit
;; TD: 
;; IP identity association relations
;; sql records (by source/dest/port) -> borealis display 
;; statistical packet analysis


(defun db-connect ()
  (postmodern:connect-toplevel
 "schnoz" "postgres" "password" "localhost")
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
  (psql-q (list "insert into packet (buffer,length,stamp) values ("
		"'" (map 'string #'code-char buffer) "',"
		(format nil "~a" len) ","
		"(select CURRENT_TIMESTAMP))")))

(defun capture-to-db ()
  (plokami:with-pcap-interface 
      (plokami::pcap "wlan0" :promisc t :snaplen 1500 :nbio t)
    (plokami:set-filter plokami::pcap "ip")
    (loop
       (plokami:capture plokami::pcap -1 
			(lambda (sec usec caplen len buffer)
			  (capture-handler sec usec caplen len buffer)))
       (sleep 0.01)))
  )

