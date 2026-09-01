;;; emcp.el --- MCP client: Streamable HTTP + OAuth 2.1 + stdio  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Author: Brent Follin
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: comm, tools
;; URL: https://github.com/bfollinprm/emcp

;;; Commentary:
;; A Model Context Protocol client for Emacs targeting spec revision
;; 2026-07-28, with backward compatibility down to 2024-11-05:
;;
;; - stdio transport (newline-delimited JSON-RPC).
;; - Streamable HTTP (per-request POST, request-scoped SSE streams,
;;   MCP-Protocol-Version / Mcp-Method / Mcp-Name / Mcp-Param-*
;;   headers, cancellation by closing the stream) over curl, so HTTPS
;;   uses the system trust store.
;; - Stateless-era `_meta' request metadata and `server/discover'
;;   probing, with fallback to the initialize-handshake era
;;   (2025-06-18/2025-03-26, `Mcp-Session-Id') and to the deprecated
;;   2024-11-05 HTTP+SSE transport.
;; - Multi Round-Trip Requests (roots / elicitation / sampling
;;   delivered as `InputRequiredResult'), and legacy server-initiated
;;   requests on old servers.
;; - OAuth 2.1 (see emcp-oauth.el) triggered automatically on 401,
;;   with step-up re-authorization on 403 insufficient_scope.
;;
;; Entry points: `emcp-connect', `emcp-tools-list', `emcp-tools-call',
;; `emcp-prompts-list', `emcp-prompts-get', `emcp-resources-list',
;; `emcp-resources-read', `emcp-listen', `emcp-close'.

;;; Code:

(require 'cl-lib)
(require 'emcp-util)
(require 'emcp-curl)
(require 'emcp-oauth)

(defconst emcp-protocol-version "2026-07-28"
  "The modern protocol revision this client speaks natively.")

(defconst emcp-legacy-versions '("2025-06-18" "2025-03-26" "2024-11-05")
  "Initialize-era protocol revisions accepted from legacy servers.")

(defconst emcp-client-version "0.1.0")

(defcustom emcp-request-timeout 120
  "Default timeout in seconds for synchronous MCP requests."
  :type 'integer :group 'emcp)

(defcustom emcp-oauth-enabled t
  "When non-nil, run the OAuth flow automatically on HTTP 401 responses."
  :type 'boolean :group 'emcp)

(defconst emcp--modern-error-codes '(-32020 -32021 -32022 -32601)
  "JSON-RPC error codes that identify a modern-era server on HTTP 4xx.")

;;;; Connection object

(cl-defstruct (emcp-connection (:constructor emcp--make-connection))
  name transport url command args env
  era                  ; modern | legacy | legacy-sse
  protocol-version session-id endpoint
  server-info server-capabilities
  tools                ; validated tools from the last tools/list
  (pending (make-hash-table :test 'eql))
  (next-id 0)
  proc sse-proc listen-proc
  roots elicitation-handler sampling-handler on-notification
  oauth auth-token access-token
  status               ; connecting | ready | closed | error
  last-error)

(defun emcp--fail (conn err)
  (setf (emcp-connection-last-error conn) err)
  (unless (memq (emcp-connection-status conn) '(ready closed))
    (setf (emcp-connection-status conn) 'error)))

;;;; Message construction

(defun emcp--next-id (conn)
  (cl-incf (emcp-connection-next-id conn)))

(defun emcp--client-capabilities (conn)
  (let (caps)
    (when (emcp-connection-roots conn)
      (push (cons 'roots (emcp-obj 'listChanged :false)) caps))
    (when (or (emcp-connection-elicitation-handler conn) (not noninteractive))
      (push (cons 'elicitation emcp-util-empty-object) caps))
    (when (emcp-connection-sampling-handler conn)
      (push (cons 'sampling emcp-util-empty-object) caps))
    (or caps emcp-util-empty-object)))

(defun emcp--wrap-params (conn params)
  "Add stateless-era _meta to PARAMS when CONN speaks the modern protocol."
  (if (not (eq (emcp-connection-era conn) 'modern))
      params
    (let ((meta
           (list (cons (intern "io.modelcontextprotocol/protocolVersion")
                       (emcp-connection-protocol-version conn))
                 (cons (intern "io.modelcontextprotocol/clientInfo")
                       (emcp-obj 'name "emcp" 'version emcp-client-version))
                 (cons (intern "io.modelcontextprotocol/clientCapabilities")
                       (emcp--client-capabilities conn)))))
      (cons (cons '_meta meta)
            (assq-delete-all '_meta (copy-alist params))))))

(defun emcp--parse-messages (body)
  "Parse BODY into a list of JSON-RPC message alists (handles batches)."
  (let ((parsed (emcp-util-json-parse body)))
    (if (and (consp parsed) (consp (car parsed)) (consp (caar parsed)))
        parsed                          ; JSON array -> batch
      (list parsed))))

;;;; Message dispatch (shared by all transports)

(defun emcp--dispatch (conn msg &optional on-notification)
  (let ((id (emcp-get msg 'id))
        (method (emcp-get msg 'method)))
    (cond
     ((and id method) (emcp--handle-server-request conn msg))
     (method
      (let ((fn (or on-notification (emcp-connection-on-notification conn))))
        (when fn
          (condition-case err
              (funcall fn method (emcp-get msg 'params))
            (error (message "emcp: notification handler error: %S" err))))))
     (id
      (let ((entry (gethash id (emcp-connection-pending conn))))
        (when entry
          (remhash id (emcp-connection-pending conn))
          (let ((err (emcp-get msg 'error)))
            (if err
                (funcall (plist-get entry :callback) 'jsonrpc-error err)
              (funcall (plist-get entry :callback) 'ok
                       (emcp-get msg 'result))))))))))

(defun emcp--resolve-pending (conn id status payload)
  (let ((entry (gethash id (emcp-connection-pending conn))))
    (when entry
      (remhash id (emcp-connection-pending conn))
      (funcall (plist-get entry :callback) status payload))))

(defun emcp--fail-all-pending (conn reason)
  (let ((pending (emcp-connection-pending conn)))
    (maphash (lambda (id entry)
               (remhash id pending)
               (funcall (plist-get entry :callback) 'transport-error reason))
             pending)))

;;;; Authentication header

(defun emcp--bearer-token (conn)
  (let ((static (emcp-connection-auth-token conn)))
    (cond ((functionp static) (funcall static))
          (static static)
          ((emcp-connection-access-token conn))
          ((and (eq (emcp-connection-transport conn) 'http)
                emcp-oauth-enabled)
           (let ((token (emcp-oauth-access-token (emcp-connection-url conn))))
             (setf (emcp-connection-access-token conn) token)
             token)))))

;;;; HTTP transport

(defun emcp--http-headers (conn method &optional name-header param-headers)
  (let ((headers `(("Content-Type" . "application/json")
                   ("Accept" . "application/json, text/event-stream"))))
    (when-let* ((token (emcp--bearer-token conn)))
      (push (cons "Authorization" (concat "Bearer " token)) headers))
    (pcase (emcp-connection-era conn)
      ('modern
       (push (cons "MCP-Protocol-Version"
                   (emcp-connection-protocol-version conn))
             headers)
       (push (cons "Mcp-Method" method) headers)
       (when name-header
         (push (cons "Mcp-Name" (emcp-util-encode-header-value name-header))
               headers))
       (setq headers (append param-headers headers)))
      ('legacy
       (when (and (not (equal method "initialize"))
                  (member (emcp-connection-protocol-version conn)
                          '("2025-06-18" "2025-11-25")))
         (push (cons "MCP-Protocol-Version"
                     (emcp-connection-protocol-version conn))
               headers))
       (when-let* ((sid (emcp-connection-session-id conn)))
         (push (cons "Mcp-Session-Id" sid) headers))))
    headers))

(cl-defun emcp--http-send (conn method params
                                &key name-header param-headers
                                on-notification callback on-headers
                                keep-stream)
  "POST one JSON-RPC request for CONN; wire the reply into CALLBACK.
CALLBACK receives (STATUS PAYLOAD) with STATUS one of ok,
jsonrpc-error, http-error, transport-error."
  (let* ((id (emcp--next-id conn))
         (msg (emcp-obj 'jsonrpc "2.0" 'id id 'method method
                        'params (emcp--wrap-params conn params)))
         (url (if (eq (emcp-connection-era conn) 'legacy-sse)
                  (emcp-connection-endpoint conn)
                (emcp-connection-url conn)))
         (proc nil))
    (puthash id (list :callback callback :on-notification on-notification)
             (emcp-connection-pending conn))
    (setq proc
          (emcp-curl
           :url url :method "POST"
           :headers (emcp--http-headers conn method name-header param-headers)
           :body (emcp-util-json-serialize msg)
           :on-headers (when on-headers
                         (lambda (_status headers) (funcall on-headers headers)))
           :on-event
           (lambda (event)
             (when-let* ((data (plist-get event :data)))
               (condition-case err
                   (dolist (m (emcp--parse-messages data))
                     (emcp--dispatch conn m on-notification))
                 (error (message "emcp: bad SSE payload: %S" err)))
               ;; The final response resolves the pending entry; close
               ;; the request-scoped stream once that has happened.
               (when (and (not keep-stream)
                          (not (gethash id (emcp-connection-pending conn))))
                 (when proc (emcp-curl-cancel proc)))))
           :callback
           (lambda (r)
             (cond
              ((plist-get r :error)
               (emcp--resolve-pending conn id 'transport-error
                                      (plist-get r :error)))
              (t
               (let ((status (plist-get r :status)))
                 (cond
                  ((plist-get r :stream)
                   ;; Stream ended; if our request never resolved, the
                   ;; server closed the stream without a response.
                   (emcp--resolve-pending
                    conn id 'transport-error
                    "SSE stream ended without a response"))
                  ((and (>= status 200) (< status 300))
                   (if (string-empty-p (string-trim (or (plist-get r :body) "")))
                       (unless (eq (emcp-connection-era conn) 'legacy-sse)
                         (emcp--resolve-pending conn id 'transport-error
                                                "Empty response body"))
                     (condition-case err
                         (dolist (m (emcp--parse-messages (plist-get r :body)))
                           (emcp--dispatch conn m on-notification))
                       (error (emcp--resolve-pending
                               conn id 'transport-error
                               (format "Unparseable response: %S" err))))))
                  (t
                   (emcp--resolve-pending
                    conn id 'http-error
                    (list :status status
                          :headers (plist-get r :headers)
                          :body (plist-get r :body)
                          :json (ignore-errors
                                  (emcp-util-json-parse
                                   (plist-get r :body)))))))))))))
    proc))

(defun emcp--http-notify (conn method params)
  "Send a fire-and-forget JSON-RPC notification over HTTP."
  (let ((msg (emcp-obj 'jsonrpc "2.0" 'method method
                       'params (emcp--wrap-params conn params))))
    (emcp-curl
     :url (if (eq (emcp-connection-era conn) 'legacy-sse)
              (emcp-connection-endpoint conn)
            (emcp-connection-url conn))
     :method "POST"
     :headers (emcp--http-headers conn method)
     :body (emcp-util-json-serialize msg)
     :callback #'ignore)))

(defun emcp--http-respond (conn response)
  "POST a JSON-RPC RESPONSE (to a legacy server-initiated request)."
  (emcp-curl
   :url (if (eq (emcp-connection-era conn) 'legacy-sse)
            (emcp-connection-endpoint conn)
          (emcp-connection-url conn))
   :method "POST"
   :headers (emcp--http-headers conn "response")
   :body (emcp-util-json-serialize response)
   :callback #'ignore))

;;;; stdio transport

(defun emcp--stdio-start (conn)
  (let* ((default-directory (expand-file-name "~/"))
         (process-environment
          (append (emcp-connection-env conn) process-environment))
         (proc (make-process
                :name (format "emcp-%s" (emcp-connection-name conn))
                :command (cons (emcp-connection-command conn)
                               (emcp-connection-args conn))
                :connection-type 'pipe
                :noquery t
                :coding '(utf-8 . utf-8)
                :stderr (get-buffer-create
                         (format " *emcp-%s-stderr*"
                                 (emcp-connection-name conn)))
                :filter
                (lambda (p chunk)
                  (let ((buf (concat (or (process-get p 'emcp-buf) "")
                                     chunk))
                        nl)
                    (while (setq nl (string-search "\n" buf))
                      (let ((line (string-trim (substring buf 0 nl))))
                        (setq buf (substring buf (1+ nl)))
                        (unless (string-empty-p line)
                          (condition-case err
                              (dolist (m (emcp--parse-messages line))
                                (emcp--dispatch conn m))
                            (error (message "emcp: bad stdio line: %S" err))))))
                    (process-put p 'emcp-buf buf)))
                :sentinel
                (lambda (p _event)
                  (unless (process-live-p p)
                    (emcp--fail-all-pending conn "stdio server exited")
                    (unless (eq (emcp-connection-status conn) 'closed)
                      (emcp--fail conn "stdio server exited")))))))
    (setf (emcp-connection-proc conn) proc)))

(defun emcp--stdio-write (conn obj)
  (process-send-string (emcp-connection-proc conn)
                       (concat (emcp-util-json-serialize obj) "\n")))

(cl-defun emcp--stdio-send (conn method params &key on-notification callback
                                 &allow-other-keys)
  (let* ((id (emcp--next-id conn))
         (msg (emcp-obj 'jsonrpc "2.0" 'id id 'method method
                        'params (emcp--wrap-params conn params))))
    (puthash id (list :callback callback :on-notification on-notification)
             (emcp-connection-pending conn))
    (emcp--stdio-write conn msg)
    nil))

(defun emcp--notify (conn method params)
  (if (eq (emcp-connection-transport conn) 'stdio)
      (emcp--stdio-write conn (emcp-obj 'jsonrpc "2.0" 'method method
                                        'params
                                        (emcp--wrap-params conn params)))
    (emcp--http-notify conn method params)))

;;;; Legacy server-initiated requests (initialize-era only)

(defun emcp--handle-server-request (conn msg)
  (let* ((id (emcp-get msg 'id))
         (method (emcp-get msg 'method))
         (params (emcp-get msg 'params))
         (response
          (condition-case err
              (pcase method
                ("ping"
                 (emcp-obj 'jsonrpc "2.0" 'id id
                           'result emcp-util-empty-object))
                ("roots/list"
                 (emcp-obj 'jsonrpc "2.0" 'id id
                           'result (emcp-obj 'roots (emcp--roots-value conn))))
                ("elicitation/create"
                 (emcp-obj 'jsonrpc "2.0" 'id id
                           'result (emcp--elicit conn params)))
                ("sampling/createMessage"
                 (if-let* ((fn (emcp-connection-sampling-handler conn)))
                     (emcp-obj 'jsonrpc "2.0" 'id id
                               'result (funcall fn conn params))
                   (emcp-obj 'jsonrpc "2.0" 'id id
                             'error (emcp-obj 'code -32601
                                              'message "Sampling not supported"))))
                (_
                 (emcp-obj 'jsonrpc "2.0" 'id id
                           'error (emcp-obj 'code -32601
                                            'message "Method not found"))))
            (error
             (emcp-obj 'jsonrpc "2.0" 'id id
                       'error (emcp-obj 'code -32603
                                        'message (format "%S" err)))))))
    (if (eq (emcp-connection-transport conn) 'stdio)
        (emcp--stdio-write conn response)
      (emcp--http-respond conn response))))

(defun emcp--roots-value (conn)
  (vconcat
   (mapcar (lambda (dir)
             (emcp-obj 'uri (concat "file://" (expand-file-name dir))
                       'name dir))
           (emcp-connection-roots conn))))

(defun emcp--elicit (conn params)
  (if-let* ((fn (emcp-connection-elicitation-handler conn)))
      (funcall fn conn params)
    (if noninteractive
        (emcp-obj 'action "decline")
      (emcp--elicit-minibuffer params))))

(defun emcp--elicit-minibuffer (params)
  "Default interactive elicitation: prompt via the minibuffer."
  (let ((message (emcp-get params 'message))
        (schema (emcp-get params 'requestedSchema)))
    (if (not (y-or-n-p (format "MCP server asks: %s  Respond? "
                               (or message "input requested"))))
        (emcp-obj 'action "decline")
      (let ((content
             (delq nil
                   (mapcar
                    (lambda (prop)
                      (when (consp prop)
                        (cons (car prop)
                              (read-string
                               (format "%s: "
                                       (or (emcp-get (cdr prop) 'description)
                                           (car prop)))))))
                    (emcp-get schema 'properties)))))
        (emcp-obj 'action "accept"
                  'content (or content emcp-util-empty-object))))))

;;;; MRTR (Multi Round-Trip Requests)

(defconst emcp--mrtr-methods '("tools/call" "resources/read" "prompts/get"))

(defun emcp--fulfill-input-requests (conn input-requests)
  "Build the InputResponses alist for INPUT-REQUESTS."
  (mapcar
   (lambda (entry)
     (let* ((req (cdr entry))
            (method (emcp-get req 'method))
            (params (emcp-get req 'params)))
       (cons (car entry)
             (pcase method
               ("roots/list" (emcp-obj 'roots (emcp--roots-value conn)))
               ("elicitation/create" (emcp--elicit conn params))
               ("sampling/createMessage"
                (if-let* ((fn (emcp-connection-sampling-handler conn)))
                    (funcall fn conn params)
                  (signal 'emcp-error
                          (list "Server requested sampling but no handler is set"))))
               (_ (signal 'emcp-error
                          (list "Unsupported input request" method)))))))
   input-requests))

;;;; Request pipeline: auth retries + MRTR + dispatch to transport

(cl-defun emcp-request-async (conn method params
                                   &key name-header param-headers
                                   on-notification callback on-headers
                                   keep-stream
                                   (auth-attempts 0) (mrtr-depth 0))
  "Send METHOD with PARAMS on CONN; invoke CALLBACK with (STATUS PAYLOAD).
Handles OAuth on 401, step-up on 403 insufficient_scope, and the MRTR
input_required loop transparently.  Returns the request process for
HTTP transports (kill it to cancel), nil for stdio."
  (let ((inner
         (lambda (status payload)
           (cond
            ;; --- OAuth: 401 unauthorized ---
            ((and (eq status 'http-error)
                  (eql (plist-get payload :status) 401)
                  (< auth-attempts 1)
                  (emcp--oauth-eligible-p conn))
             (emcp--auth-retry conn method params payload nil
                               (list :name-header name-header
                                     :param-headers param-headers
                                     :on-notification on-notification
                                     :on-headers on-headers
                                     :keep-stream keep-stream
                                     :auth-attempts (1+ auth-attempts)
                                     :mrtr-depth mrtr-depth)
                               callback))
            ;; --- OAuth: 403 insufficient_scope step-up ---
            ((and (eq status 'http-error)
                  (eql (plist-get payload :status) 403)
                  (< auth-attempts 2)
                  (emcp--oauth-eligible-p conn)
                  (let ((ch (emcp--challenge-of payload)))
                    (equal (cdr (assoc "error" (plist-get ch :params)))
                           "insufficient_scope")))
             (emcp--auth-retry conn method params payload t
                               (list :name-header name-header
                                     :param-headers param-headers
                                     :on-notification on-notification
                                     :on-headers on-headers
                                     :keep-stream keep-stream
                                     :auth-attempts (1+ auth-attempts)
                                     :mrtr-depth mrtr-depth)
                               callback))
            ;; --- MRTR: input_required interim result ---
            ((and (eq status 'ok)
                  (member method emcp--mrtr-methods)
                  (equal (emcp-get payload 'resultType) "input_required")
                  (< mrtr-depth 5))
             (run-at-time
              0 nil
              (lambda ()
                (condition-case err
                    (let* ((responses
                            (when (emcp-get payload 'inputRequests)
                              (emcp--fulfill-input-requests
                               conn (emcp-get payload 'inputRequests))))
                           (request-state (emcp-get payload 'requestState))
                           (next-params
                            (append
                             (emcp-obj 'inputResponses (or responses nil)
                                       'requestState request-state)
                             (cl-remove-if
                              (lambda (kv)
                                (memq (car-safe kv)
                                      '(inputResponses requestState _meta)))
                              (or params nil)))))
                      (emcp-request-async
                       conn method next-params
                       :name-header name-header
                       :param-headers param-headers
                       :on-notification on-notification
                       :callback callback
                       :auth-attempts auth-attempts
                       :mrtr-depth (1+ mrtr-depth)))
                  (error (funcall callback 'transport-error
                                  (format "MRTR fulfillment failed: %S"
                                          err)))))))
            (t (funcall callback status payload))))))
    (if (eq (emcp-connection-transport conn) 'stdio)
        (emcp--stdio-send conn method params
                          :on-notification on-notification :callback inner)
      (emcp--http-send conn method params
                       :name-header name-header
                       :param-headers param-headers
                       :on-notification on-notification
                       :on-headers on-headers
                       :keep-stream keep-stream
                       :callback inner))))

(defun emcp--oauth-eligible-p (conn)
  (and emcp-oauth-enabled
       (eq (emcp-connection-transport conn) 'http)
       (null (emcp-connection-auth-token conn))))

(defun emcp--challenge-of (payload)
  (emcp-util-parse-www-authenticate
   (emcp-util-header (plist-get payload :headers) "www-authenticate")))

(defun emcp--auth-retry (conn method params payload step-up opts callback)
  "Run the OAuth flow off the process-filter stack, then retry METHOD."
  (run-at-time
   0 nil
   (lambda ()
     (condition-case err
         (let* ((challenge (emcp--challenge-of payload))
                (token (if step-up
                           (emcp-oauth-step-up (emcp-connection-url conn)
                                               (emcp-connection-oauth conn)
                                               challenge)
                         (emcp-oauth-authorize (emcp-connection-url conn)
                                               (emcp-connection-oauth conn)
                                               challenge))))
           (setf (emcp-connection-access-token conn) token)
           (apply #'emcp-request-async conn method params
                  (append opts (list :callback callback))))
       (error (funcall callback 'http-error
                       (append payload (list :oauth-error err))))))))

;;;; Connection establishment

(cl-defun emcp-connect (&key name url command args env roots
                             elicitation-handler sampling-handler
                             on-notification oauth auth-token
                             (timeout 60) callback)
  "Connect to an MCP server; return the connection.
Provide :url for HTTP(S) servers or :command/:args for stdio servers.
Optional: :roots (list of directories), :elicitation-handler,
:sampling-handler, :on-notification (fn METHOD PARAMS), :oauth
\(plist: :client-id :client-secret :client-metadata-url :scopes
:issuer), :auth-token (static bearer token string or function).
Blocks until ready unless :callback is given (called with the
connection once ready, or signalled data on failure)."
  (unless (or url command)
    (signal 'emcp-error (list "emcp-connect needs :url or :command")))
  (let ((conn (emcp--make-connection
               :name (or name (or url command))
               :transport (if url 'http 'stdio)
               :url url :command command :args args :env env
               :roots roots
               :elicitation-handler elicitation-handler
               :sampling-handler sampling-handler
               :on-notification on-notification
               :oauth oauth :auth-token auth-token
               :status 'connecting)))
    (if url
        (emcp--connect-http conn)
      (emcp--connect-stdio conn))
    (if callback
        (progn
          (run-at-time
           0.05 nil
           (lambda ()
             (emcp-curl-await
              (lambda () (memq (emcp-connection-status conn) '(ready error)))
              timeout "connect")
             (funcall callback conn)))
          conn)
      (emcp-curl-await
       (lambda () (memq (emcp-connection-status conn) '(ready error)))
       timeout "connect")
      (when (eq (emcp-connection-status conn) 'error)
        (signal 'emcp-error (list "Connection failed"
                                  (emcp-connection-last-error conn))))
      conn)))

(defun emcp--connect-http (conn)
  "Probe the modern era first; fall back through the legacy eras."
  (setf (emcp-connection-era conn) 'modern
        (emcp-connection-protocol-version conn) emcp-protocol-version)
  (emcp-request-async
   conn "server/discover" nil
   :callback
   (lambda (status payload)
     (pcase status
       ('ok
        (setf (emcp-connection-server-info conn)
              (or (emcp-get payload 'serverInfo) payload)
              (emcp-connection-server-capabilities conn)
              (emcp-get payload 'capabilities)
              (emcp-connection-status conn) 'ready))
       ('jsonrpc-error
        (emcp--discover-error conn payload))
       ('http-error
        (let* ((code (emcp-get (plist-get payload :json) 'error 'code)))
          (cond
           ((memq code emcp--modern-error-codes)
            (emcp--discover-error conn (emcp-get (plist-get payload :json)
                                                 'error)))
           ((memq (plist-get payload :status) '(400 404 405))
            (emcp--connect-legacy conn nil))
           (t (emcp--fail conn payload)))))
       (_ (emcp--fail conn payload))))))

(defun emcp--discover-error (conn err)
  "Handle a modern-era JSON-RPC error from the server/discover probe."
  (let ((code (emcp-get err 'code)))
    (cond
     ((eql code -32601)
      ;; Modern server without server/discover; proceed optimistically.
      (setf (emcp-connection-status conn) 'ready))
     ((eql code -32022)
      (let* ((supported (emcp-get err 'data 'supported))
             (version (cl-find-if (lambda (v) (member v supported))
                                  emcp-legacy-versions)))
        (if version
            (emcp--connect-legacy conn version)
          (emcp--fail conn (list "No mutually supported protocol version"
                                 supported)))))
     (t (emcp--fail conn err)))))

(defun emcp--connect-legacy (conn version)
  "Attempt an initialize-era Streamable HTTP connection."
  (setf (emcp-connection-era conn) 'legacy
        (emcp-connection-protocol-version conn) (or version "2025-06-18"))
  (emcp-request-async
   conn "initialize"
   (emcp-obj 'protocolVersion (emcp-connection-protocol-version conn)
             'capabilities (emcp--client-capabilities conn)
             'clientInfo (emcp-obj 'name "emcp" 'version emcp-client-version))
   :on-headers
   (lambda (headers)
     (when-let* ((sid (emcp-util-header headers "mcp-session-id")))
       (setf (emcp-connection-session-id conn) sid)))
   :callback
   (lambda (status payload)
     (pcase status
       ('ok
        (let ((server-version (emcp-get payload 'protocolVersion)))
          (if (not (or (member server-version emcp-legacy-versions)
                       (member server-version '("2025-11-25"))))
              (emcp--fail conn (list "Unsupported server protocol version"
                                     server-version))
            (setf (emcp-connection-protocol-version conn)
                  server-version
                  (emcp-connection-server-info conn)
                  (emcp-get payload 'serverInfo)
                  (emcp-connection-server-capabilities conn)
                  (emcp-get payload 'capabilities))
            (emcp--notify conn "notifications/initialized" nil)
            (setf (emcp-connection-status conn) 'ready))))
       ('http-error
        (if (and (eq (emcp-connection-transport conn) 'http)
                 (memq (plist-get payload :status) '(400 404 405)))
            (emcp--connect-legacy-sse conn)
          (emcp--fail conn payload)))
       (_ (emcp--fail conn payload))))))

(defun emcp--connect-legacy-sse (conn)
  "Fall back to the deprecated 2024-11-05 HTTP+SSE transport."
  (setf (emcp-connection-era conn) 'legacy-sse
        (emcp-connection-protocol-version conn) "2024-11-05")
  (let* ((headers `(("Accept" . "text/event-stream")))
         (got-endpoint nil))
    (when-let* ((token (emcp--bearer-token conn)))
      (push (cons "Authorization" (concat "Bearer " token)) headers))
    (setf (emcp-connection-sse-proc conn)
          (emcp-curl
           :url (emcp-connection-url conn) :method "GET" :headers headers
           :on-event
           (lambda (event)
             (pcase (plist-get event :event)
               ("endpoint"
                (setq got-endpoint t)
                (setf (emcp-connection-endpoint conn)
                      (url-expand-file-name (plist-get event :data)
                                            (emcp-connection-url conn)))
                (emcp--legacy-sse-initialize conn))
               ("message"
                (condition-case err
                    (dolist (m (emcp--parse-messages (plist-get event :data)))
                      (emcp--dispatch conn m))
                  (error (message "emcp: bad SSE message: %S" err))))))
           :callback
           (lambda (r)
             (unless (eq (emcp-connection-status conn) 'closed)
               (emcp--fail-all-pending conn "SSE stream closed")
               (emcp--fail conn (or (plist-get r :error)
                                    (format "SSE stream closed (HTTP %s)"
                                            (plist-get r :status))))))))
    (run-at-time 15 nil
                 (lambda ()
                   (unless (or got-endpoint
                               (memq (emcp-connection-status conn)
                                     '(ready closed error)))
                     (when (emcp-connection-sse-proc conn)
                       (emcp-curl-cancel (emcp-connection-sse-proc conn)))
                     (emcp--fail conn "No endpoint event from SSE server"))))))

(defun emcp--legacy-sse-initialize (conn)
  (emcp-request-async
   conn "initialize"
   (emcp-obj 'protocolVersion "2024-11-05"
             'capabilities (emcp--client-capabilities conn)
             'clientInfo (emcp-obj 'name "emcp" 'version emcp-client-version))
   :callback
   (lambda (status payload)
     (if (eq status 'ok)
         (progn
           (setf (emcp-connection-server-info conn)
                 (emcp-get payload 'serverInfo)
                 (emcp-connection-server-capabilities conn)
                 (emcp-get payload 'capabilities))
           (emcp--notify conn "notifications/initialized" nil)
           (setf (emcp-connection-status conn) 'ready))
       (emcp--fail conn payload)))))

(defun emcp--connect-stdio (conn)
  (emcp--stdio-start conn)
  (setf (emcp-connection-era conn) 'modern
        (emcp-connection-protocol-version conn) emcp-protocol-version)
  (let* ((answered nil)
         (timer nil))
    (emcp-request-async
     conn "server/discover" nil
     :callback
     (lambda (status payload)
       (setq answered t)
       (when timer (cancel-timer timer))
       (pcase status
         ('ok
          (setf (emcp-connection-server-info conn)
                (or (emcp-get payload 'serverInfo) payload)
                (emcp-connection-server-capabilities conn)
                (emcp-get payload 'capabilities)
                (emcp-connection-status conn) 'ready))
         ('jsonrpc-error
          (if (eql (emcp-get payload 'code) -32022)
              (emcp--discover-error conn payload)
            (emcp--stdio-legacy-init conn)))
         (_ (emcp--fail conn payload)))))
    (setq timer
          (run-at-time 5 nil
                       (lambda ()
                         (unless answered
                           ;; No reply to the probe: assume initialize era.
                           (emcp--stdio-legacy-init conn)))))))

(defun emcp--stdio-legacy-init (conn)
  (setf (emcp-connection-era conn) 'legacy
        (emcp-connection-protocol-version conn) "2025-06-18")
  (emcp-request-async
   conn "initialize"
   (emcp-obj 'protocolVersion "2025-06-18"
             'capabilities (emcp--client-capabilities conn)
             'clientInfo (emcp-obj 'name "emcp" 'version emcp-client-version))
   :callback
   (lambda (status payload)
     (if (and (eq status 'ok)
              (member (emcp-get payload 'protocolVersion)
                      (cons "2025-11-25" emcp-legacy-versions)))
         (progn
           (setf (emcp-connection-protocol-version conn)
                 (emcp-get payload 'protocolVersion)
                 (emcp-connection-server-info conn)
                 (emcp-get payload 'serverInfo)
                 (emcp-connection-server-capabilities conn)
                 (emcp-get payload 'capabilities))
           (emcp--notify conn "notifications/initialized" nil)
           (setf (emcp-connection-status conn) 'ready))
       (emcp--fail conn payload)))))

;;;; Synchronous request helper

(cl-defun emcp-request (conn method params &rest opts
                             &key (timeout emcp-request-timeout)
                             &allow-other-keys)
  "Synchronously send METHOD with PARAMS on CONN; return the result alist.
Signals `emcp-jsonrpc-error', `emcp-http-error', or `emcp-error'."
  (let (outcome)
    (apply #'emcp-request-async conn method params
           :callback (lambda (status payload)
                       (setq outcome (list status payload)))
           (cl-loop for (k v) on opts by #'cddr
                    unless (memq k '(:timeout :callback))
                    append (list k v)))
    (emcp-curl-await (lambda () outcome) timeout method)
    (pcase (car outcome)
      ('ok (cadr outcome))
      ('jsonrpc-error
       (signal 'emcp-jsonrpc-error
               (list method
                     (emcp-get (cadr outcome) 'code)
                     (emcp-get (cadr outcome) 'message)
                     (cadr outcome))))
      ('http-error
       (signal 'emcp-http-error
               (list method (plist-get (cadr outcome) :status)
                     (cadr outcome))))
      (_ (signal 'emcp-error (list method (cadr outcome)))))))

;;;; Public API

(defun emcp-tools-list (conn)
  "List tools on CONN.  Invalid tool definitions (per the x-mcp-header
constraints) are rejected with a warning, per spec.  Caches the result
for header construction in `emcp-tools-call'."
  (let ((tools nil) (cursor nil) (first t))
    (while (or first cursor)
      (setq first nil)
      (let ((result (emcp-request conn "tools/list"
                                  (when cursor (emcp-obj 'cursor cursor)))))
        (setq cursor (emcp-get result 'nextCursor))
        (dolist (tool (emcp-get result 'tools))
          (condition-case err
              (progn
                (when (eq (emcp-connection-era conn) 'modern)
                  (emcp-util-tool-header-map tool)) ; validation
                (push tool tools))
            (emcp-invalid-tool
             (message "emcp: rejecting tool %S: %S"
                      (emcp-get tool 'name) err))))))
    (setq tools (nreverse tools))
    (setf (emcp-connection-tools conn) tools)
    tools))

(cl-defun emcp-tools-call (conn name &optional arguments
                                &key on-notification (retry-mismatch t))
  "Call tool NAME with ARGUMENTS (alist or hash table) on CONN."
  (unless (emcp-connection-tools conn) (emcp-tools-list conn))
  (let* ((tool (cl-find-if (lambda (tl) (equal (emcp-get tl 'name) name))
                           (emcp-connection-tools conn)))
         (param-headers (when (and tool
                                   (eq (emcp-connection-era conn) 'modern)
                                   (eq (emcp-connection-transport conn) 'http))
                          (emcp-util-param-headers tool arguments)))
         (params (emcp-obj 'name name
                           'arguments (or arguments emcp-util-empty-object))))
    (condition-case err
        (emcp-request conn "tools/call" params
                      :name-header name
                      :param-headers param-headers
                      :on-notification on-notification)
      (emcp-jsonrpc-error
       ;; HeaderMismatch: the tool schema may have changed; refresh and
       ;; retry once with fresh headers, per spec guidance.
       (if (and retry-mismatch (eql (nth 2 err) -32020))
           (progn
             (emcp-tools-list conn)
             (emcp-tools-call conn name arguments
                              :on-notification on-notification
                              :retry-mismatch nil))
         (signal (car err) (cdr err)))))))

(defun emcp-prompts-list (conn)
  "List prompts available on CONN."
  (emcp-get (emcp-request conn "prompts/list" nil) 'prompts))

(defun emcp-prompts-get (conn name &optional arguments)
  "Get prompt NAME with ARGUMENTS on CONN."
  (emcp-request conn "prompts/get"
                (emcp-obj 'name name
                          'arguments (or arguments emcp-util-empty-object))
                :name-header name))

(defun emcp-resources-list (conn)
  "List resources available on CONN."
  (emcp-get (emcp-request conn "resources/list" nil) 'resources))

(defun emcp-resources-templates-list (conn)
  "List resource templates available on CONN."
  (emcp-get (emcp-request conn "resources/templates/list" nil)
            'resourceTemplates))

(defun emcp-resources-read (conn uri)
  "Read resource URI on CONN."
  (emcp-request conn "resources/read" (emcp-obj 'uri uri) :name-header uri))

(defun emcp-listen (conn types callback)
  "Open a long-lived subscriptions/listen stream (modern servers only).
TYPES is a list of change-notification type strings, e.g.
\(\"toolsListChanged\" \"resourcesListChanged\").  CALLBACK receives
\(METHOD PARAMS) for each notification.  Returns a handle for
`emcp-unlisten'."
  (unless (eq (emcp-connection-era conn) 'modern)
    (signal 'emcp-error (list "subscriptions/listen requires a modern server")))
  (let ((proc (emcp-request-async
               conn "subscriptions/listen"
               (emcp-obj 'notifications (vconcat types))
               :keep-stream t
               :on-notification callback
               :callback (lambda (_status _payload) nil))))
    (setf (emcp-connection-listen-proc conn) proc)
    proc))

(defun emcp-unlisten (conn)
  "Close CONN's subscriptions/listen stream."
  (when-let* ((proc (emcp-connection-listen-proc conn)))
    (emcp-curl-cancel proc)
    (setf (emcp-connection-listen-proc conn) nil)))

(defun emcp-close (conn)
  "Close CONN, terminating any legacy session and killing processes."
  (when (and (eq (emcp-connection-era conn) 'legacy)
             (emcp-connection-session-id conn)
             (eq (emcp-connection-transport conn) 'http))
    (ignore-errors
      (emcp-curl :url (emcp-connection-url conn) :method "DELETE"
                 :headers `(("Mcp-Session-Id"
                             . ,(emcp-connection-session-id conn)))
                 :callback #'ignore)))
  (setf (emcp-connection-status conn) 'closed)
  (emcp-unlisten conn)
  (when-let* ((p (emcp-connection-sse-proc conn))) (emcp-curl-cancel p))
  (when-let* ((p (emcp-connection-proc conn)))
    (when (process-live-p p) (delete-process p)))
  (emcp--fail-all-pending conn "connection closed")
  nil)

(provide 'emcp)
;;; emcp.el ends here
