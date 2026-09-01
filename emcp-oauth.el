;;; emcp-oauth.el --- OAuth 2.1 authorization for emcp  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Author: Brent Follin
;; Version: 0.1.0

;;; Commentary:
;; OAuth 2.1 client per the MCP 2026-07-28 authorization spec:
;;
;; - 401 handling with WWW-Authenticate parsing, plus well-known
;;   fallback probing for Protected Resource Metadata (RFC 9728).
;; - Authorization server metadata discovery: RFC 8414 and OpenID
;;   Connect Discovery, path-insertion before path-appending, with
;;   issuer validation.
;; - Client registration: pre-registered client_id, Client ID Metadata
;;   Documents (client_id = HTTPS URL), or Dynamic Client Registration
;;   (RFC 7591, deprecated fallback), keyed per issuer.
;; - Authorization code + PKCE (S256), `state', `resource' (RFC 8707)
;;   on both authorization and token requests, and `iss' validation
;;   (RFC 9207) before code redemption.
;; - Loopback redirect listener (RFC 8252) on 127.0.0.1.
;; - Refresh tokens and step-up (insufficient_scope) re-authorization,
;;   with token persistence keyed by canonical resource URI.

;;; Code:

(require 'cl-lib)
(require 'plstore)
(require 'browse-url)
(require 'emcp-util)
(require 'emcp-curl)

(defcustom emcp-oauth-store-file
  (expand-file-name "emcp-oauth.plstore" user-emacs-directory)
  "File where emcp persists OAuth tokens and client registrations.
Created with 0600 permissions.  Tokens are stored unencrypted by
default; point `plstore-encrypt-to' at a GPG key and set
`emcp-oauth-use-secret-storage' to store them encrypted."
  :type 'file :group 'emcp)

(defcustom emcp-oauth-use-secret-storage nil
  "When non-nil, store tokens in plstore secret (GPG-encrypted) fields."
  :type 'boolean :group 'emcp)

(defcustom emcp-oauth-browse-function #'browse-url
  "Function called with the authorization URL to start the user consent step."
  :type 'function :group 'emcp)

(defcustom emcp-oauth-timeout 300
  "Seconds to wait for the browser-based authorization to complete."
  :type 'integer :group 'emcp)

(defcustom emcp-oauth-client-name "emcp (Emacs MCP client)"
  "client_name sent during Dynamic Client Registration."
  :type 'string :group 'emcp)

;;;; Persistence

(defvar emcp-oauth--store nil)

(defun emcp-oauth--store ()
  (unless emcp-oauth--store
    (setq emcp-oauth--store (plstore-open emcp-oauth-store-file))
    (ignore-errors (set-file-modes emcp-oauth-store-file #o600)))
  emcp-oauth--store)

(defun emcp-oauth--store-get (id)
  (cdr (plstore-get (emcp-oauth--store) id)))

(defun emcp-oauth--store-put (id plist)
  (let ((store (emcp-oauth--store)))
    (if emcp-oauth-use-secret-storage
        (plstore-put store id nil plist)
      (plstore-put store id plist nil))
    (plstore-save store)
    (ignore-errors (set-file-modes emcp-oauth-store-file #o600))))

(defun emcp-oauth-forget (resource-url)
  "Delete stored tokens for RESOURCE-URL."
  (interactive "sMCP server URL: ")
  (let ((store (emcp-oauth--store)))
    (plstore-delete store (emcp-util-canonical-resource resource-url))
    (plstore-save store)))

;;;; Small HTTP helpers

(defun emcp-oauth--get-json (url)
  "GET URL; return parsed JSON on 200, nil otherwise."
  (condition-case nil
      (let ((r (emcp-curl-sync :url url :method "GET"
                               :headers '(("Accept" . "application/json"))
                               :timeout 15)))
        (when (= 200 (plist-get r :status))
          (emcp-util-json-parse (plist-get r :body))))
    (error nil)))

(defun emcp-oauth--post-form (url form &optional basic-auth)
  "POST FORM (alist) to URL as x-www-form-urlencoded; return (STATUS . JSON)."
  (let* ((headers `(("Content-Type" . "application/x-www-form-urlencoded")
                    ("Accept" . "application/json")
                    ,@(when basic-auth
                        `(("Authorization"
                           . ,(concat "Basic "
                                      (base64-encode-string
                                       (encode-coding-string basic-auth 'utf-8)
                                       t)))))))
         (r (emcp-curl-sync :url url :method "POST" :headers headers
                            :body (emcp-util-form-encode form) :timeout 30)))
    (cons (plist-get r :status)
          (ignore-errors (emcp-util-json-parse (plist-get r :body))))))

;;;; Protected Resource Metadata discovery (RFC 9728)

(defun emcp-oauth--well-known-prm-urls (server-url)
  "Well-known PRM URLs for SERVER-URL, path-suffixed form first."
  (let* ((u (url-generic-parse-url server-url))
         (origin (concat (url-type u) "://" (url-host u)
                         (let ((p (url-portspec u)))
                           (if p (format ":%d" p) ""))))
         (path (car (url-path-and-query u))))
    (delete-dups
     (delq nil
           (list (when (and path (not (member path '("" "/"))))
                   (concat origin "/.well-known/oauth-protected-resource" path))
                 (concat origin "/.well-known/oauth-protected-resource"))))))

(defun emcp-oauth--fetch-prm (server-url challenge)
  "Fetch Protected Resource Metadata for SERVER-URL.
CHALLENGE is the parsed WWW-Authenticate plist (or nil).  Return the
parsed metadata alist; signal `emcp-oauth-error' when unavailable."
  (let ((from-header
         (cdr (assoc "resource_metadata" (plist-get challenge :params)))))
    (or (and from-header (emcp-oauth--get-json from-header))
        (cl-loop for url in (emcp-oauth--well-known-prm-urls server-url)
                 for doc = (emcp-oauth--get-json url)
                 when doc return doc)
        (signal 'emcp-oauth-error
                (list "No protected resource metadata found" server-url)))))

;;;; Authorization server metadata discovery (RFC 8414 / OIDC)

(defun emcp-oauth--as-metadata-urls (issuer)
  "Discovery URLs for ISSUER in spec priority order."
  (let* ((u (url-generic-parse-url issuer))
         (origin (concat (url-type u) "://" (url-host u)
                         (let ((p (url-portspec u)))
                           (if p (format ":%d" p) ""))))
         (path (car (url-path-and-query u))))
    (if (member path '("" "/"))
        (list (concat origin "/.well-known/oauth-authorization-server")
              (concat origin "/.well-known/openid-configuration"))
      (list (concat origin "/.well-known/oauth-authorization-server" path)
            (concat origin "/.well-known/openid-configuration" path)
            (concat origin path "/.well-known/openid-configuration")))))

(defun emcp-oauth--discover-as (issuer)
  "Discover and validate authorization server metadata for ISSUER."
  (or (cl-loop for url in (emcp-oauth--as-metadata-urls issuer)
               for doc = (emcp-oauth--get-json url)
               when doc
               return (if (equal (emcp-get doc 'issuer) issuer)
                          doc
                        (signal 'emcp-oauth-error
                                (list "AS metadata issuer mismatch"
                                      issuer (emcp-get doc 'issuer)))))
      (signal 'emcp-oauth-error
              (list "No authorization server metadata found" issuer))))

;;;; Client registration

(defun emcp-oauth--client-for (issuer as-meta config redirect-uri)
  "Return (CLIENT-ID . CLIENT-SECRET) for ISSUER.
CONFIG is the connection's :oauth plist.  Uses, in order: configured
client-id, configured Client ID Metadata Document URL, a persisted
registration for ISSUER, then Dynamic Client Registration."
  (cond
   ((plist-get config :client-id)
    (cons (plist-get config :client-id) (plist-get config :client-secret)))
   ((plist-get config :client-metadata-url)
    (cons (plist-get config :client-metadata-url) nil))
   ((let ((saved (emcp-oauth--store-get (concat "client:" issuer))))
      (when-let* ((id (plist-get saved :client-id)))
        (cons id (plist-get saved :client-secret)))))
   (t
    (let ((endpoint (emcp-get as-meta 'registration_endpoint)))
      (unless endpoint
        (signal 'emcp-oauth-error
                (list "No client_id configured and AS offers no registration"
                      issuer)))
      (let* ((r (emcp-curl-sync
                 :url endpoint :method "POST"
                 :headers '(("Content-Type" . "application/json")
                            ("Accept" . "application/json"))
                 :body (emcp-util-json-serialize
                        (emcp-obj
                         'client_name emcp-oauth-client-name
                         'redirect_uris (vector redirect-uri)
                         'grant_types (vector "authorization_code"
                                              "refresh_token")
                         'response_types (vector "code")
                         'token_endpoint_auth_method "none"
                         'application_type "native"))
                 :timeout 30))
             (status (plist-get r :status))
             (doc (and (memq status '(200 201))
                       (emcp-util-json-parse (plist-get r :body)))))
        (unless doc
          (signal 'emcp-oauth-error
                  (list "Dynamic client registration failed" status
                        (plist-get r :body))))
        (let ((id (emcp-get doc 'client_id))
              (secret (emcp-get doc 'client_secret)))
          (emcp-oauth--store-put
           (concat "client:" issuer)
           (list :client-id id
                 :client-secret (and (stringp secret) secret)
                 :redirect-uri redirect-uri))
          (cons id (and (stringp secret) secret))))))))

;;;; Loopback redirect listener (RFC 8252)

(defun emcp-oauth--start-loopback (on-callback)
  "Start a loopback HTTP listener on 127.0.0.1.
ON-CALLBACK receives the parsed query alist of the /callback request.
Return the server process; its port is (process-contact PROC :service)."
  (make-network-process
   :name "emcp-oauth-loopback"
   :server t :host "127.0.0.1" :service t :noquery t
   :coding '(binary . binary)
   :filter
   (lambda (client chunk)
     (let ((buf (concat (or (process-get client 'emcp-buf) "") chunk)))
       (process-put client 'emcp-buf buf)
       (when (string-match "\\`\\([A-Z]+\\) \\([^ ]+\\) HTTP" buf)
         (let* ((target (match-string 2 buf))
                (u (url-generic-parse-url target))
                (path-query (url-path-and-query u))
                (path (car path-query)))
           (if (string-prefix-p "/callback" path)
               (progn
                 (process-send-string
                  client
                  (concat "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/html; charset=utf-8\r\n"
                          "Connection: close\r\n\r\n"
                          "<html><body><h1>emcp: authorization received</h1>"
                          "<p>You can close this window and return to Emacs."
                          "</p></body></html>"))
                 (run-at-time 0.1 nil #'delete-process client)
                 (funcall on-callback
                          (emcp-util-query-parse (cdr path-query))))
             (process-send-string
              client "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
             (run-at-time 0.1 nil #'delete-process client))))))))

;;;; Token store accessors

(defun emcp-oauth-stored (resource)
  "Return the stored token plist for canonical RESOURCE, or nil."
  (emcp-oauth--store-get resource))

(defun emcp-oauth--save-tokens (resource issuer token-response scopes
                                         &optional fallback-refresh)
  (let ((expires-in (emcp-get token-response 'expires_in))
        (refresh (emcp-get token-response 'refresh_token)))
    (emcp-oauth--store-put
     resource
     (list :access-token (emcp-get token-response 'access_token)
           :refresh-token (if (stringp refresh) refresh fallback-refresh)
           :expires-at (and (numberp expires-in)
                            (+ (float-time) expires-in -60))
           :scope (or (emcp-get token-response 'scope) scopes)
           :issuer issuer))))

(defun emcp-oauth-access-token (resource-url)
  "Return a valid access token for RESOURCE-URL, refreshing if possible.
Return nil when there is no usable token."
  (let* ((resource (emcp-util-canonical-resource resource-url))
         (saved (emcp-oauth--store-get resource)))
    (when saved
      (let ((token (plist-get saved :access-token))
            (expires-at (plist-get saved :expires-at)))
        (if (and token (or (null expires-at) (< (float-time) expires-at)))
            token
          (emcp-oauth--refresh resource saved))))))

(defun emcp-oauth--refresh (resource saved)
  "Refresh the token for RESOURCE using SAVED plist; return token or nil."
  (let ((refresh (plist-get saved :refresh-token))
        (issuer (plist-get saved :issuer)))
    (when (and refresh issuer)
      (condition-case nil
          (let* ((as-meta (emcp-oauth--discover-as issuer))
                 (client (emcp-oauth--store-get (concat "client:" issuer)))
                 (client-id (plist-get client :client-id))
                 (client-secret (plist-get client :client-secret))
                 (reply (emcp-oauth--post-form
                         (emcp-get as-meta 'token_endpoint)
                         (delq nil
                               (list (cons "grant_type" "refresh_token")
                                     (cons "refresh_token" refresh)
                                     (cons "resource" resource)
                                     (and client-id (not client-secret)
                                          (cons "client_id" client-id))))
                         (and client-secret
                              (concat client-id ":" client-secret)))))
            (when (and (= 200 (car reply)) (cdr reply))
              (emcp-oauth--save-tokens resource issuer (cdr reply)
                                       (plist-get saved :scope)
                                       refresh)
              (emcp-get (cdr reply) 'access_token)))
        (error nil)))))

;;;; Scope selection (spec: Scope Selection Strategy)

(defun emcp-oauth--select-scope (challenge prm config previous)
  "Pick the scope string to request, or nil to omit the parameter.
Priority: union with PREVIOUS of the CHALLENGE scope; else PRM
scopes_supported; else CONFIG :scopes."
  (let* ((challenge-scope
          (cdr (assoc "scope" (plist-get challenge :params))))
         (base (cond (challenge-scope challenge-scope)
                     ((emcp-get prm 'scopes_supported)
                      (mapconcat #'identity
                                 (emcp-get prm 'scopes_supported) " "))
                     ((plist-get config :scopes) (plist-get config :scopes))))
         (all (delete-dups
               (append (and previous (split-string previous " " t))
                       (and base (split-string base " " t))))))
    (when all (mapconcat #'identity all " "))))

;;;; The authorization flow

(defun emcp-oauth-authorize (server-url config &optional challenge previous-scope)
  "Run the OAuth 2.1 authorization code + PKCE flow for SERVER-URL.
CONFIG is the connection's :oauth plist; CHALLENGE the parsed 401/403
WWW-Authenticate plist, if any; PREVIOUS-SCOPE a space-separated scope
string to preserve during step-up.  Blocks (pumping process output)
until the browser round-trip completes; returns the access token."
  (let* ((resource (emcp-util-canonical-resource server-url))
         (prm (emcp-oauth--fetch-prm server-url challenge))
         (issuers (emcp-get prm 'authorization_servers))
         (issuer (or (plist-get config :issuer) (car issuers))))
    (unless issuer
      (signal 'emcp-oauth-error
              (list "Protected resource metadata lists no authorization server"
                    resource)))
    (when (and (plist-get config :issuer)
               issuers
               (not (member issuer issuers)))
      (signal 'emcp-oauth-error
              (list "Configured issuer not offered by resource" issuer)))
    (let* ((as-meta (emcp-oauth--discover-as issuer))
           (result nil)
           (listener
            (emcp-oauth--start-loopback
             (lambda (query) (setq result query))))
           (port (process-contact listener :service))
           (redirect-uri (format "http://127.0.0.1:%d/callback" port)))
      (unwind-protect
          (let* ((client (emcp-oauth--client-for issuer as-meta config
                                                 redirect-uri))
                 (client-id (car client))
                 (client-secret (cdr client))
                 (pkce (emcp-util-pkce-pair))
                 (state (emcp-util-random-token))
                 (scope (emcp-oauth--select-scope challenge prm config
                                                  previous-scope))
                 (auth-url
                  (concat
                   (emcp-get as-meta 'authorization_endpoint)
                   (if (string-search "?" (emcp-get as-meta
                                                    'authorization_endpoint))
                       "&" "?")
                   (emcp-util-form-encode
                    (delq nil
                          (list (cons "response_type" "code")
                                (cons "client_id" client-id)
                                (cons "redirect_uri" redirect-uri)
                                (cons "state" state)
                                (cons "code_challenge" (cdr pkce))
                                (cons "code_challenge_method" "S256")
                                (cons "resource" resource)
                                (and scope (cons "scope" scope))))))))
            (funcall emcp-oauth-browse-function auth-url)
            (emcp-curl-await (lambda () result) emcp-oauth-timeout
                             "OAuth authorization")
            ;; State and RFC 9207 iss validation, before touching the code.
            (unless (equal (cdr (assoc "state" result)) state)
              (signal 'emcp-oauth-error (list "OAuth state mismatch")))
            (unless (emcp-util-validate-iss
                     (cdr (assoc "iss" result)) issuer
                     (eq (emcp-get as-meta
                                   'authorization_response_iss_parameter_supported)
                         t))
              (signal 'emcp-oauth-error
                      (list "OAuth iss validation failed"
                            (cdr (assoc "iss" result)))))
            (when-let* ((err (cdr (assoc "error" result))))
              (signal 'emcp-oauth-error
                      (list "Authorization error" err
                            (cdr (assoc "error_description" result)))))
            (let ((code (cdr (assoc "code" result))))
              (unless code
                (signal 'emcp-oauth-error
                        (list "Authorization response carried no code")))
              (let ((reply (emcp-oauth--post-form
                            (emcp-get as-meta 'token_endpoint)
                            (delq nil
                                  (list (cons "grant_type" "authorization_code")
                                        (cons "code" code)
                                        (cons "redirect_uri" redirect-uri)
                                        (cons "code_verifier" (car pkce))
                                        (cons "resource" resource)
                                        (unless client-secret
                                          (cons "client_id" client-id))))
                            (and client-secret
                                 (concat client-id ":" client-secret)))))
                (unless (and (= 200 (car reply))
                             (emcp-get (cdr reply) 'access_token))
                  (signal 'emcp-oauth-error
                          (list "Token request failed" (car reply)
                                (cdr reply))))
                (emcp-oauth--save-tokens resource issuer (cdr reply) scope)
                (emcp-get (cdr reply) 'access_token))))
        (when (process-live-p listener) (delete-process listener))))))

(defun emcp-oauth-step-up (server-url config challenge)
  "Re-authorize SERVER-URL with the union of previous and challenged scopes."
  (let ((previous (plist-get
                   (emcp-oauth-stored
                    (emcp-util-canonical-resource server-url))
                   :scope)))
    (emcp-oauth-authorize server-url config challenge previous)))

(provide 'emcp-oauth)
;;; emcp-oauth.el ends here
