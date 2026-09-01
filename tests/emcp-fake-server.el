;;; emcp-fake-server.el --- In-Emacs HTTP server for emcp tests  -*- lexical-binding: t; -*-

;;; Commentary:
;; A tiny HTTP/1.1 server over `make-network-process' used by the
;; integration tests.  One request per connection (Connection: close).
;; The handler receives a request plist (:method :path :query :headers
;; :body) and returns either
;;   (:status N :headers ALIST :body STRING)
;; or
;;   (:status N :headers ALIST :sse EVENTS)
;; where EVENTS is a list of (EVENT-TYPE . DATA) pairs streamed as SSE.

;;; Code:

(require 'cl-lib)
(require 'emcp-util)

(defun emcp-fake-server-start (handler)
  "Start a local HTTP server calling HANDLER per request.
Return (PROC . PORT)."
  (let ((proc
         (make-network-process
          :name "emcp-fake-server"
          :server t :host "127.0.0.1" :service t :noquery t
          :coding '(binary . binary)
          :filter (lambda (client chunk)
                    (emcp-fake-server--filter client chunk handler)))))
    (cons proc (process-contact proc :service))))

(defun emcp-fake-server-stop (server)
  (when (process-live-p (car server))
    (delete-process (car server))))

(defun emcp-fake-server--filter (client chunk handler)
  (let ((buf (concat (or (process-get client 'emcp-buf) "") chunk)))
    (process-put client 'emcp-buf buf)
    (let ((head (emcp-util-parse-http-head-request buf)))
      (when head
        (cl-destructuring-bind (method target headers body-start) head
          (let* ((content-length
                  (string-to-number
                   (or (emcp-util-header headers "content-length") "0")))
                 (body (substring buf body-start)))
            (when (>= (length body) content-length)
              (process-put client 'emcp-buf "")
              (let* ((u (url-generic-parse-url target))
                     (path-query (url-path-and-query u))
                     (request (list :method method
                                    :path (car path-query)
                                    :query (cdr path-query)
                                    :headers headers
                                    :body (decode-coding-string
                                           (substring body 0 content-length)
                                           'utf-8)))
                     (response
                      (condition-case err
                          (funcall handler request)
                        (error (list :status 500 :body (format "%S" err))))))
                (emcp-fake-server--respond client response)))))))))

(defun emcp-util-parse-http-head-request (text)
  "Parse an HTTP request head from TEXT.
Return (METHOD TARGET HEADERS BODY-START) or nil if incomplete."
  (let ((head-end (string-search "\r\n\r\n" text)))
    (when head-end
      (let ((head (substring text 0 head-end)))
        (unless (string-match "\\`\\([A-Z]+\\) \\([^ ]+\\) HTTP" head)
          (error "Malformed request line: %s" head))
        (let ((method (match-string 1 head))
              (target (match-string 2 head))
              (headers nil))
          (dolist (line (cdr (split-string head "\r\n")))
            (when (string-match "\\`\\([^:]+\\):[ \t]*\\(.*\\)\\'" line)
              (push (cons (downcase (match-string 1 line))
                          (match-string 2 line))
                    headers)))
          (list method target (nreverse headers) (+ head-end 4)))))))

(defun emcp-fake-server--respond (client response)
  (let* ((status (or (plist-get response :status) 200))
         (extra (plist-get response :headers))
         (sse (plist-get response :sse))
         (body (plist-get response :body))
         (reason (pcase status
                   (200 "OK") (201 "Created") (202 "Accepted")
                   (400 "Bad Request") (401 "Unauthorized")
                   (403 "Forbidden") (404 "Not Found")
                   (405 "Method Not Allowed") (_ "Status"))))
    (if sse
        (progn
          (process-send-string
           client
           (concat (format "HTTP/1.1 %d %s\r\n" status reason)
                   "Content-Type: text/event-stream\r\n"
                   (mapconcat (lambda (kv)
                                (format "%s: %s\r\n" (car kv) (cdr kv)))
                              extra "")
                   "Connection: close\r\n\r\n"))
          (dolist (event sse)
            (process-send-string
             client
             (concat (unless (equal (car event) "message")
                       (format "event: %s\n" (car event)))
                     (mapconcat (lambda (line) (format "data: %s\n" line))
                                (split-string (cdr event) "\n") "")
                     "\n")))
          (run-at-time 0.1 nil (lambda ()
                                 (when (process-live-p client)
                                   (delete-process client)))))
      (let ((encoded (encode-coding-string (or body "") 'utf-8)))
        (process-send-string
         client
         (concat (format "HTTP/1.1 %d %s\r\n" status reason)
                 (unless (assoc "Content-Type" extra)
                   "Content-Type: application/json\r\n")
                 (mapconcat (lambda (kv)
                              (format "%s: %s\r\n" (car kv) (cdr kv)))
                            extra "")
                 (format "Content-Length: %d\r\n" (length encoded))
                 "Connection: close\r\n\r\n"
                 encoded)))
      (run-at-time 0.1 nil (lambda ()
                             (when (process-live-p client)
                               (delete-process client)))))))

(provide 'emcp-fake-server)
;;; emcp-fake-server.el ends here
