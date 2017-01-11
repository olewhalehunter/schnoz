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

(defun parse-whois (str)

  (list org-name address netrange)
)
