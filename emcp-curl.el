;;; emcp-curl.el --- curl-based HTTP layer for emcp  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Author: Brent Follin
;; Version: 0.1.0

;;; Commentary:
;; Async HTTP client on top of a curl subprocess.  curl provides TLS
;; (system trust store), HTTP/2, proxies, and chunked decoding.  Each
;; request is its own process, so cancelling a request — the Streamable
;; HTTP cancellation signal — is killing the process, which closes the
;; connection.  SSE response bodies are parsed incrementally and
;; delivered event-by-event.

;;; Code:

(require 'cl-lib)
(require 'emcp-util)

(defgroup emcp nil "Model Context Protocol client." :group 'comm)

(defcustom emcp-curl-program "curl"
  "Path to the curl executable."
  :type 'string :group 'emcp)

(defcustom emcp-curl-connect-timeout 10
  "Connection timeout in seconds passed to curl."
  :type 'integer :group 'emcp)

(cl-defstruct emcp-curl--state
  phase          ; head | body
  buf            ; unparsed bytes
  status headers
  stream-p       ; text/event-stream response
  sse-parser
  body-parts     ; reversed list of body chunks (non-stream)
  on-event on-headers callback
  config-file    ; temp file carrying headers, deleted on exit
  done cancelled)

(defun emcp-curl--config-file (headers)
  "Write HEADERS to a 0600 temp curl config file; return its name.
Keeps header values (e.g. bearer tokens) off the process command line.
Signals `emcp-error' on CR/LF in a name or value (header injection)."
  (let ((file (make-temp-file "emcp-curl" nil ".conf")))
    (with-temp-file file
      (dolist (kv headers)
        (let ((name (format "%s" (car kv)))
              (value (format "%s" (cdr kv))))
          (when (or (string-match-p "[\r\n]" name)
                    (string-match-p "[\r\n]" value))
            (delete-file file)
            (signal 'emcp-error
                    (list "Refusing CR/LF in HTTP header" name)))
          (insert "header = \""
                  (replace-regexp-in-string
                   "\"" "\\\\\""
                   (replace-regexp-in-string
                    "\\\\" "\\\\\\\\"
                    ;; "Name:" with no value tells curl to drop the header.
                    (if (string-empty-p value)
                        (concat name ":")
                      (concat name ": " value))))
                  "\"\n"))))
    file))

(cl-defun emcp-curl (&key url (method "GET") headers body timeout
                          on-event on-headers callback)
  "Issue an async HTTP request via curl; return the process.
HEADERS is an alist of (NAME . VALUE).  BODY is a string (implies the
given METHOD with a request body).  ON-EVENT, when the response is an
SSE stream, receives (:event TYPE :data DATA :id ID) plists as they
arrive.  ON-HEADERS, if given, fires with (STATUS HEADERS) as soon as
the response head is parsed.  CALLBACK receives a plist: on success
\(:status N :headers ALIST :body STRING :stream BOOL), on transport
failure (:error MSG).  For SSE responses CALLBACK fires when the
stream ends."
  (let* ((config-file (when headers
                        (emcp-curl--config-file
                         (cons '("Expect" . "") headers))))
         (args `("-sS" "-i" "--no-buffer"
                 "--connect-timeout" ,(number-to-string emcp-curl-connect-timeout)
                 ,@(when timeout (list "--max-time" (number-to-string timeout)))
                 "-X" ,method
                 ,@(when config-file (list "--config" config-file))
                 ;; Body arrives via stdin: no argv exposure or size limit.
                 ,@(when body (list "--data-binary" "@-"))
                 ,url))
         (state (make-emcp-curl--state
                 :phase 'head :buf "" :body-parts nil
                 :on-event on-event :on-headers on-headers
                 :callback callback :config-file config-file))
         (proc (make-process
                :name "emcp-curl"
                :command (cons emcp-curl-program args)
                :connection-type 'pipe
                :noquery t
                :coding '(binary . binary)
                :filter #'emcp-curl--filter
                :sentinel #'emcp-curl--sentinel)))
    (process-put proc 'emcp-curl-state state)
    (when body
      (process-send-string proc (if (multibyte-string-p body)
                                    (encode-coding-string body 'utf-8)
                                  body))
      (process-send-eof proc))
    proc))

(defun emcp-curl--cleanup (state)
  (when-let* ((file (emcp-curl--state-config-file state)))
    (setf (emcp-curl--state-config-file state) nil)
    (ignore-errors (delete-file file))))

(defun emcp-curl-cancel (proc)
  "Cancel the request PROC; no callbacks fire after this."
  (let ((state (process-get proc 'emcp-curl-state)))
    (when state
      (setf (emcp-curl--state-cancelled state) t)
      (emcp-curl--cleanup state)))
  (when (process-live-p proc)
    (delete-process proc)))

(defun emcp-curl--filter (proc chunk)
  (let ((state (process-get proc 'emcp-curl-state)))
    (when (and state (not (emcp-curl--state-cancelled state)))
      (condition-case err
          (emcp-curl--feed state chunk)
        (error (message "emcp-curl: error in filter: %S" err))))))

(defun emcp-curl--feed (state chunk)
  (if (eq (emcp-curl--state-phase state) 'head)
      (progn
        (setf (emcp-curl--state-buf state)
              (concat (emcp-curl--state-buf state) chunk))
        (let ((parsed (emcp-util-parse-http-head (emcp-curl--state-buf state))))
          (when parsed
            (cl-destructuring-bind (status headers body-start) parsed
              (setf (emcp-curl--state-status state) status
                    (emcp-curl--state-headers state) headers
                    (emcp-curl--state-phase state) 'body
                    (emcp-curl--state-stream-p state)
                    (let ((ct (emcp-util-header headers "content-type")))
                      (and ct (string-prefix-p "text/event-stream" ct))))
              (when (emcp-curl--state-stream-p state)
                (setf (emcp-curl--state-sse-parser state)
                      (emcp-util-make-sse-parser)))
              (when-let* ((fn (emcp-curl--state-on-headers state)))
                (funcall fn status headers))
              (let ((rest (substring (emcp-curl--state-buf state) body-start)))
                (setf (emcp-curl--state-buf state) "")
                (unless (string-empty-p rest)
                  (emcp-curl--body state rest)))))))
    (emcp-curl--body state chunk)))

(defun emcp-curl--body (state chunk)
  (if (emcp-curl--state-stream-p state)
      (funcall (emcp-curl--state-sse-parser state) chunk
               (lambda (event)
                 (unless (emcp-curl--state-cancelled state)
                   (when-let* ((fn (emcp-curl--state-on-event state)))
                     (funcall fn event)))))
    (push chunk (emcp-curl--state-body-parts state))))

(defun emcp-curl--sentinel (proc _event)
  (when (memq (process-status proc) '(exit signal))
    (let ((state (process-get proc 'emcp-curl-state)))
      (when state (emcp-curl--cleanup state))
      (when (and state
                 (not (emcp-curl--state-done state))
                 (not (emcp-curl--state-cancelled state)))
        (setf (emcp-curl--state-done state) t)
        (let ((cb (emcp-curl--state-callback state)))
          (when cb
            (condition-case err
                (if (emcp-curl--state-status state)
                    (funcall cb
                             (list :status (emcp-curl--state-status state)
                                   :headers (emcp-curl--state-headers state)
                                   :body (mapconcat
                                          #'identity
                                          (nreverse
                                           (emcp-curl--state-body-parts state))
                                          "")
                                   :stream (emcp-curl--state-stream-p state)))
                  (funcall cb
                           (list :error
                                 (format "curl exited %s before a response%s"
                                         (process-exit-status proc)
                                         (let ((b (emcp-curl--state-buf state)))
                                           (if (string-empty-p b) ""
                                             (concat ": " (string-trim b))))))))
              (error (message "emcp-curl: error in callback: %S" err)))))))))

(defun emcp-curl-await (pred &optional timeout what)
  "Pump process output until PRED returns non-nil; return its value.
Signal `emcp-timeout' after TIMEOUT seconds (default 30)."
  (let ((deadline (+ (float-time) (or timeout 30)))
        result)
    (while (not (setq result (funcall pred)))
      (when (> (float-time) deadline)
        (signal 'emcp-timeout (list (or what "request"))))
      (accept-process-output nil 0.05))
    result))

(cl-defun emcp-curl-sync (&rest args &key timeout &allow-other-keys)
  "Synchronous `emcp-curl'.  Return the callback plist; signal on :error."
  (let (result)
    (apply #'emcp-curl
           (append (list :callback (lambda (r) (setq result r)))
                   args))
    (emcp-curl-await (lambda () result) (or timeout 30) "HTTP request")
    (when (plist-get result :error)
      (signal 'emcp-http-error (list (plist-get result :error))))
    result))

(provide 'emcp-curl)
;;; emcp-curl.el ends here
