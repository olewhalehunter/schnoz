;; whois lookup and caching for IP addr and identity association

(defmacro with-input-from-command ((stream-name command args) &body body) 
  `(with-open-stream
       (,stream-name
	(sb-ext:process-output (sb-ext:run-program ,command
						   ,args
						   :search t
						   :output :stream)))
     ,@body))

(defmacro sys-read (command args)
  "shell command output as string"
  (let ((istream (gensym))
        (ostream (gensym))
        (line (gensym)))
    `(with-input-from-command (,istream ,command ,args)
       (with-output-to-string (,ostream)
         (loop (let ((,line (read-line ,istream nil)))
                 (when (null ,line) (return))
                 (write-line ,line ,ostream)))))))

(defun whois (addr)
  (setq whois-result (sys-read whois-bin-loc (list addr)))
  
  (format nil "whois lookup result: ~a" whois-result)
)

(setq *scanners* (make-hash-table))
(defun get-scanner (name)
  (gethash name *scanners*))
(defun scanner (begin-token end-token)
  (cl-ppcre::create-scanner (concatenate 'string
					 begin-token "(.+?)" end-token)))
(defun puthash (key hash-table object)
  (setf (gethash key hash-table) object))
(defun scanners-to-ht (list-of-scanners ht)
  (dolist (l list-of-scanners)
    (destructuring-bind (name begin-token end-token)
        l
      (puthash name ht (scanner begin-token end-token)))))
(scanners-to-ht 
 '(
   (org-name "OrgName:" "")
   (address "Address" "")
   )
 *scanners*) 

(defun scrape-delim (scanner url)
  (cl-ppcre:all-matches-as-strings 
   scanner
   (whois url)))

(defun parse-whois (url)
    
  (setq fields (list
   (scrape-delim (get-scanner 'address) url)
   (scrape-delim (get-scanner 'org-name) url)))

  (format t "~a" fields)

  fields
)
