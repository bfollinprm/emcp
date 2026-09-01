;;; emcp-integration-test.el --- End-to-end tests against a fake server  -*- lexical-binding: t; -*-

;;; Commentary:
;; Integration tests that run the real client (curl transport and all)
;; against an in-Emacs fake HTTP server: modern-era happy path with
;; header mirroring, MRTR, legacy initialize fallback, and the full
;; OAuth 2.1 flow (PRM discovery, AS metadata, DCR, PKCE, loopback
;; redirect, token exchange, authenticated retry).

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'emcp)
(require 'emcp-fake-server)

(defun emcp-itest--body (request)
  (emcp-util-json-parse (plist-get request :body)))

(defun emcp-itest--jsonrpc (id result)
  (list :status 200
        :body (emcp-util-json-serialize
               (emcp-obj 'jsonrpc "2.0" 'id id 'result result))))

(defconst emcp-itest--discover-result
  (emcp-obj 'resultType "complete"
            'serverInfo (emcp-obj 'name "fake" 'version "1.0")
            'protocolVersions (vector "2026-07-28")
            'capabilities emcp-util-empty-object))

(defmacro emcp-itest--with-server (handler-var handler &rest body)
  "Run BODY with a fake server bound; URL available as `url'."
  (declare (indent 2))
  `(let* ((,handler-var ,handler)
          (server (emcp-fake-server-start ,handler-var))
          (url (format "http://127.0.0.1:%d/mcp" (cdr server))))
     (ignore url)
     (unwind-protect
         (progn ,@body)
       (emcp-fake-server-stop server))))

;;;; Modern era: discover, tools/list validation, header mirroring, SSE

(ert-deftest emcp-itest-modern-tools-call ()
  (let ((seen nil))    ; log of (METHOD . REQUEST) for assertions
    (emcp-itest--with-server
        handler
        (lambda (request)
          (let* ((body (emcp-itest--body request))
                 (method (emcp-get body 'method))
                 (id (emcp-get body 'id)))
            (push (cons method request) seen)
            (pcase method
              ("server/discover"
               (emcp-itest--jsonrpc id emcp-itest--discover-result))
              ("tools/list"
               (emcp-itest--jsonrpc
                id
                (emcp-obj
                 'resultType "complete" 'ttlMs 60000 'cacheScope "private"
                 'tools
                 (vector
                  (emcp-obj 'name "execute_sql"
                            'description "run sql"
                            'inputSchema
                            (emcp-obj
                             'type "object"
                             'properties
                             (emcp-obj
                              'region (emcp-obj 'type "string"
                                                (intern "x-mcp-header") "Region")
                              'query (emcp-obj 'type "string"))))
                  ;; Invalid: x-mcp-header under items; must be rejected.
                  (emcp-obj 'name "bad_tool"
                            'inputSchema
                            (emcp-obj
                             'type "object"
                             'properties
                             (emcp-obj
                              'xs (emcp-obj
                                   'type "array"
                                   'items (emcp-obj
                                           'type "string"
                                           (intern "x-mcp-header") "X")))))))))
              ("tools/call"
               (list :status 200
                     :sse (list
                           (cons "message"
                                 (emcp-util-json-serialize
                                  (emcp-obj 'jsonrpc "2.0"
                                            'method "notifications/progress"
                                            'params (emcp-obj 'progress 50))))
                           (cons "message"
                                 (emcp-util-json-serialize
                                  (emcp-obj 'jsonrpc "2.0" 'id id
                                            'result
                                            (emcp-obj 'resultType "complete"
                                                      'content (vector)
                                                      'ok t)))))))
              (_ (list :status 404 :body "{}")))))
      (let ((conn (emcp-connect :name "it-modern" :url url :timeout 15)))
        (unwind-protect
            (progn
              (should (eq (emcp-connection-era conn) 'modern))
              ;; Invalid tool rejected, valid one kept.
              (let ((tools (emcp-tools-list conn)))
                (should (= 1 (length tools)))
                (should (equal (emcp-get (car tools) 'name) "execute_sql")))
              ;; Call with a mirrored parameter; collect notifications.
              (let* ((notes nil)
                     (result (emcp-tools-call
                              conn "execute_sql"
                              '((region . "us-west1") (query . "SELECT 1"))
                              :on-notification
                              (lambda (method _params) (push method notes)))))
                (should (eq (emcp-get result 'ok) t))
                (should (member "notifications/progress" notes)))
              ;; Header assertions on the wire.
              (let ((call (cdr (assoc "tools/call" seen))))
                (should call)
                (let ((headers (plist-get call :headers))
                      (body (emcp-itest--body call)))
                  (should (equal (emcp-util-header headers "mcp-protocol-version")
                                 "2026-07-28"))
                  (should (equal (emcp-util-header headers "mcp-method")
                                 "tools/call"))
                  (should (equal (emcp-util-header headers "mcp-name")
                                 "execute_sql"))
                  (should (equal (emcp-util-header headers "mcp-param-region")
                                 "us-west1"))
                  (should (equal (emcp-get body 'params '_meta
                                           (intern "io.modelcontextprotocol/protocolVersion"))
                                 "2026-07-28"))
                  (should (emcp-get body 'params '_meta
                                    (intern "io.modelcontextprotocol/clientInfo"))))))
          (emcp-close conn))))))

;;;; MRTR: input_required -> fulfil -> retry with requestState echo

(ert-deftest emcp-itest-mrtr-elicitation ()
  (let ((call-ids nil))
    (emcp-itest--with-server
        handler
        (lambda (request)
          (let* ((body (emcp-itest--body request))
                 (method (emcp-get body 'method))
                 (id (emcp-get body 'id)))
            (pcase method
              ("server/discover"
               (emcp-itest--jsonrpc id emcp-itest--discover-result))
              ("tools/list"
               (emcp-itest--jsonrpc
                id (emcp-obj 'resultType "complete"
                             'tools (vector (emcp-obj
                                             'name "login"
                                             'inputSchema
                                             (emcp-obj 'type "object"))))))
              ("tools/call"
               (push id call-ids)
               (let ((responses (emcp-get body 'params 'inputResponses)))
                 (if (null responses)
                     (emcp-itest--jsonrpc
                      id
                      (emcp-obj
                       'resultType "input_required"
                       'inputRequests
                       (emcp-obj 'github_login
                                 (emcp-obj 'method "elicitation/create"
                                           'params
                                           (emcp-obj 'mode "form"
                                                     'message "username?")))
                       'requestState "blob42"))
                   ;; Retry: verify echo and the fulfilled response.
                   (if (and (equal (emcp-get body 'params 'requestState)
                                   "blob42")
                            (equal (emcp-get responses 'github_login 'action)
                                   "accept")
                            (equal (emcp-get responses 'github_login
                                             'content 'name)
                                   "octocat"))
                       (emcp-itest--jsonrpc
                        id (emcp-obj 'resultType "complete" 'granted t))
                     (list :status 200
                           :body (emcp-util-json-serialize
                                  (emcp-obj 'jsonrpc "2.0" 'id id
                                            'error (emcp-obj
                                                    'code -32602
                                                    'message "bad retry"))))))))
              (_ (list :status 404 :body "{}")))))
      (let ((conn (emcp-connect
                   :name "it-mrtr" :url url :timeout 15
                   :elicitation-handler
                   (lambda (_conn _params)
                     (emcp-obj 'action "accept"
                               'content (emcp-obj 'name "octocat"))))))
        (unwind-protect
            (let ((result (emcp-tools-call conn "login" nil)))
              (should (eq (emcp-get result 'granted) t))
              ;; Two independent requests with distinct ids.
              (should (= 2 (length call-ids)))
              (should-not (eql (car call-ids) (cadr call-ids))))
          (emcp-close conn))))))

;;;; Legacy fallback: initialize handshake + session header

(ert-deftest emcp-itest-legacy-initialize-fallback ()
  (let ((seen nil))
    (emcp-itest--with-server
        handler
        (lambda (request)
          (let* ((body (ignore-errors (emcp-itest--body request)))
                 (method (and body (emcp-get body 'method)))
                 (id (and body (emcp-get body 'id))))
            (push (cons (or method "?") request) seen)
            (pcase method
              ;; A legacy server: unknown modern method -> plain 400.
              ("server/discover"
               (list :status 400
                     :headers '(("Content-Type" . "text/plain"))
                     :body "bad request"))
              ("initialize"
               (if (equal (emcp-get body 'params 'protocolVersion)
                          "2025-06-18")
                   (append (emcp-itest--jsonrpc
                            id
                            (emcp-obj 'protocolVersion "2025-06-18"
                                      'serverInfo (emcp-obj 'name "old"
                                                            'version "0.9")
                                      'capabilities emcp-util-empty-object))
                           '(:headers (("Mcp-Session-Id" . "sess-1"))))
                 (list :status 400 :body "{}")))
              ("notifications/initialized" (list :status 202 :body ""))
              ("tools/list"
               (emcp-itest--jsonrpc
                id (emcp-obj 'tools
                             (vector (emcp-obj 'name "legacy_tool"
                                               'inputSchema
                                               (emcp-obj 'type "object"))))))
              (_ (list :status 404 :body "{}")))))
      (let ((conn (emcp-connect :name "it-legacy" :url url :timeout 15)))
        (unwind-protect
            (progn
              (should (eq (emcp-connection-era conn) 'legacy))
              (should (equal (emcp-connection-protocol-version conn)
                             "2025-06-18"))
              (should (equal (emcp-connection-session-id conn) "sess-1"))
              (let ((tools (emcp-tools-list conn)))
                (should (equal (emcp-get (car tools) 'name) "legacy_tool")))
              ;; Session id and version header on the follow-up request.
              (let ((list-req (cdr (assoc "tools/list" seen))))
                (should (equal (emcp-util-header (plist-get list-req :headers)
                                                 "mcp-session-id")
                               "sess-1"))
                (should (equal (emcp-util-header (plist-get list-req :headers)
                                                 "mcp-protocol-version")
                               "2025-06-18"))
                ;; No modern header mirroring in the legacy era.
                (should-not (emcp-util-header (plist-get list-req :headers)
                                              "mcp-method"))
                ;; No _meta in legacy params.
                (should-not (emcp-get (emcp-itest--body list-req)
                                      'params '_meta))))
          (emcp-close conn))))))

;;;; OAuth 2.1: 401 -> discovery -> DCR -> PKCE -> loopback -> token -> retry

(ert-deftest emcp-itest-oauth-full-flow ()
  (let* ((store-file (make-temp-file "emcp-oauth-test" nil ".plstore"))
         (state (list :challenge nil :code-redeemed nil :authed-requests 0))
         (origin nil) (issuer nil))
    (delete-file store-file)
    (emcp-itest--with-server
        handler
        (lambda (request)
          (let ((path (plist-get request :path))
                (headers (plist-get request :headers)))
            (cond
             ;; --- Protected resource metadata ---
             ((equal path "/.well-known/oauth-protected-resource")
              (list :status 200
                    :body (emcp-util-json-serialize
                           (emcp-obj 'resource (concat origin "/mcp")
                                     'authorization_servers (vector issuer)
                                     'scopes_supported (vector "mcp:read")))))
             ;; --- AS metadata (path-insertion form, tried first) ---
             ((equal path "/.well-known/oauth-authorization-server/as")
              (list :status 200
                    :body (emcp-util-json-serialize
                           (emcp-obj
                            'issuer issuer
                            'authorization_endpoint (concat issuer "/authorize")
                            'token_endpoint (concat issuer "/token")
                            'registration_endpoint (concat issuer "/register")
                            'authorization_response_iss_parameter_supported t))))
             ;; --- Dynamic client registration ---
             ((equal path "/as/register")
              (let ((reg (emcp-itest--body request)))
                (unless (equal (emcp-get reg 'token_endpoint_auth_method) "none")
                  (error "unexpected auth method"))
                (unless (equal (emcp-get reg 'application_type) "native")
                  (error "missing application_type"))
                (list :status 201
                      :body (emcp-util-json-serialize
                             (emcp-obj 'client_id "test-client")))))
             ;; --- Token endpoint ---
             ((equal path "/as/token")
              (let* ((form (emcp-util-query-parse (plist-get request :body)))
                     (verifier (cdr (assoc "code_verifier" form))))
                (if (and (equal (cdr (assoc "grant_type" form))
                                "authorization_code")
                        (equal (cdr (assoc "code" form)) "authcode-1")
                        (equal (cdr (assoc "resource" form))
                               (concat origin "/mcp"))
                        verifier
                        (equal (emcp-util-pkce-challenge verifier)
                               (plist-get state :challenge)))
                    (progn
                      (plist-put state :code-redeemed t)
                      (list :status 200
                            :body (emcp-util-json-serialize
                                   (emcp-obj 'access_token "tok123"
                                             'token_type "Bearer"
                                             'expires_in 3600
                                             'refresh_token "refresh-1"
                                             'scope "mcp:read"))))
                  (list :status 400
                        :body (emcp-util-json-serialize
                               (emcp-obj 'error "invalid_grant"))))))
             ;; --- The MCP endpoint itself ---
             ((equal path "/mcp")
              (let ((auth (emcp-util-header headers "authorization")))
                (if (not (equal auth "Bearer tok123"))
                    (list :status 401
                          :headers
                          `(("WWW-Authenticate"
                             . ,(format
                                 "Bearer resource_metadata=\"%s\", scope=\"mcp:read\""
                                 (concat origin
                                         "/.well-known/oauth-protected-resource")))))
                  (plist-put state :authed-requests
                             (1+ (plist-get state :authed-requests)))
                  (let* ((body (emcp-itest--body request))
                         (id (emcp-get body 'id)))
                    (pcase (emcp-get body 'method)
                      ("server/discover"
                       (emcp-itest--jsonrpc id emcp-itest--discover-result))
                      ("tools/list"
                       (emcp-itest--jsonrpc
                        id (emcp-obj 'resultType "complete"
                                     'tools (vector))))
                      (_ (list :status 404 :body "{}")))))))
             (t (list :status 404 :body "not found")))))
      (setq origin (substring url 0 (- (length url) 4))  ; strip "/mcp"
            issuer (concat origin "/as"))
      (let* ((emcp-oauth-store-file store-file)
             (emcp-oauth--store nil)
             (emcp-oauth-use-secret-storage nil)
             (auth-url-seen nil)
             (emcp-oauth-browse-function
              ;; Stand-in for the user's browser: validate the
              ;; authorization URL, then hit the loopback redirect.
              (lambda (auth-url)
                (setq auth-url-seen auth-url)
                (let* ((query (emcp-util-query-parse
                               (cadr (split-string auth-url "?"))))
                       (redirect (cdr (assoc "redirect_uri" query))))
                  (plist-put state :challenge
                             (cdr (assoc "code_challenge" query)))
                  (should (equal (cdr (assoc "code_challenge_method" query))
                                 "S256"))
                  (should (equal (cdr (assoc "resource" query))
                                 (concat origin "/mcp")))
                  (should (equal (cdr (assoc "client_id" query))
                                 "test-client"))
                  (should (equal (cdr (assoc "scope" query)) "mcp:read"))
                  (emcp-curl
                   :url (concat redirect "?"
                                (emcp-util-form-encode
                                 (list (cons "code" "authcode-1")
                                       (cons "state"
                                             (cdr (assoc "state" query)))
                                       (cons "iss" issuer))))
                   :method "GET" :callback #'ignore)))))
        (let ((conn (emcp-connect :name "it-oauth" :url url :timeout 30)))
          (unwind-protect
              (progn
                (should (eq (emcp-connection-status conn) 'ready))
                (should auth-url-seen)
                (should (plist-get state :code-redeemed))
                (should (equal (emcp-tools-list conn) nil))
                (should (>= (plist-get state :authed-requests) 2))
                ;; Tokens persisted for reuse, keyed by canonical resource.
                (let ((saved (emcp-oauth-stored (concat origin "/mcp"))))
                  (should (equal (plist-get saved :access-token) "tok123"))
                  (should (equal (plist-get saved :refresh-token) "refresh-1"))
                  (should (equal (plist-get saved :issuer) issuer))))
            (emcp-close conn)
            (ignore-errors (delete-file store-file))))))))

;;;; stdio transport: modern era

(defconst emcp-itest--stdio-server
  (expand-file-name "fake_stdio_server.py"
                    (file-name-directory
                     (or load-file-name buffer-file-name))))

(ert-deftest emcp-itest-stdio-modern ()
  (skip-unless (executable-find "python3"))
  (let ((conn (emcp-connect :name "it-stdio"
                            :command "python3"
                            :args (list emcp-itest--stdio-server "modern")
                            :timeout 15)))
    (unwind-protect
        (progn
          (should (eq (emcp-connection-era conn) 'modern))
          (should (equal (emcp-get (emcp-connection-server-info conn) 'name)
                         "fake-stdio"))
          (let ((tools (emcp-tools-list conn)))
            (should (equal (emcp-get (car tools) 'name) "echo")))
          (let ((result (emcp-tools-call conn "echo" '((x . "y")))))
            (should (equal (emcp-get result 'echoed 'x) "y"))))
      (emcp-close conn))))

(ert-deftest emcp-itest-stdio-legacy ()
  (skip-unless (executable-find "python3"))
  (let ((conn (emcp-connect :name "it-stdio-legacy"
                            :command "python3"
                            :args (list emcp-itest--stdio-server "legacy")
                            :timeout 20)))
    (unwind-protect
        (progn
          (should (eq (emcp-connection-era conn) 'legacy))
          (should (equal (emcp-connection-protocol-version conn) "2025-06-18"))
          (let ((tools (emcp-tools-list conn)))
            (should (equal (emcp-get (car tools) 'name) "old_echo"))))
      (emcp-close conn))))

(provide 'emcp-integration-test)
;;; emcp-integration-test.el ends here
