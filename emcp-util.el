;;; emcp-util.el --- Pure helpers for the emcp MCP client  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Author: Brent Follin
;; Version: 0.1.0

;;; Commentary:
;; Pure, side-effect-free helpers used across the emcp package:
;; JSON wrappers, base64url/PKCE, HTTP header value encoding
;; (Base64 sentinel format), WWW-Authenticate parsing, an incremental
;; SSE parser, HTTP response-head parsing, x-mcp-header schema walking,
;; and canonical resource URI computation.

;;; Code:

(require 'cl-lib)
(require 'url-parse)
(require 'url-util)
(require 'url-expand)

(define-error 'emcp-error "MCP error")
(define-error 'emcp-timeout "MCP timeout" 'emcp-error)
(define-error 'emcp-invalid-tool "Invalid MCP tool definition" 'emcp-error)
(define-error 'emcp-jsonrpc-error "MCP JSON-RPC error" 'emcp-error)
(define-error 'emcp-http-error "MCP HTTP error" 'emcp-error)
(define-error 'emcp-oauth-error "MCP OAuth error" 'emcp-error)

;;;; JSON

(defun emcp-util-json-parse (string)
  "Parse JSON STRING into alists/lists.  Null is :null, false is :false."
  (json-parse-string
   (if (multibyte-string-p string) string (decode-coding-string string 'utf-8))
   :object-type 'alist :array-type 'list
   :null-object :null :false-object :false))

(defun emcp-util-json-serialize (object)
  "Serialize OBJECT to a JSON string.  :null is null, :false is false.
Arrays must be vectors; alists/hash tables are objects."
  (json-serialize object :null-object :null :false-object :false))

(defun emcp-obj (&rest kvs)
  "Build an alist object from KVS (KEY VALUE ...), dropping nil values.
Use :false for JSON false and vectors for arrays."
  (let (out)
    (while kvs
      (let ((k (pop kvs)) (v (pop kvs)))
        (when v (push (cons k v) out))))
    (nreverse out)))

(defun emcp-get (obj &rest keys)
  "Look up nested symbol KEYS in parsed-JSON alist OBJ.
JSON null (:null) is returned as nil, so absent and null look alike."
  (dolist (k keys)
    (setq obj (and (listp obj) (cdr (assq k obj)))))
  (if (eq obj :null) nil obj))

(defconst emcp-util-empty-object (make-hash-table :test 'equal :size 1)
  "Shared value that serializes to the empty JSON object {}.")

;;;; Randomness / PKCE

(defun emcp-util-random-bytes (n)
  "Return N random bytes as a unibyte string, preferring /dev/urandom."
  (or (ignore-errors
        (with-temp-buffer
          (set-buffer-multibyte nil)
          (let ((coding-system-for-read 'binary))
            (call-process "head" "/dev/urandom" '(t nil) nil
                          "-c" (number-to-string n)))
          (when (= (buffer-size) n) (buffer-string))))
      (progn
        (random t)
        (apply #'unibyte-string
               (cl-loop repeat n collect (random 256))))))

(defun emcp-util-base64url (bytes)
  "Base64url-encode unibyte string BYTES without padding."
  (let ((s (base64-encode-string bytes t)))
    (setq s (replace-regexp-in-string "\\+" "-" s))
    (setq s (replace-regexp-in-string "/" "_" s))
    (replace-regexp-in-string "=+\\'" "" s)))

(defun emcp-util-pkce-challenge (verifier)
  "Return the S256 code challenge for VERIFIER."
  (emcp-util-base64url (secure-hash 'sha256 verifier nil nil t)))

(defun emcp-util-pkce-pair ()
  "Return (VERIFIER . CHALLENGE) for a fresh PKCE S256 pair."
  (let ((verifier (emcp-util-base64url (emcp-util-random-bytes 32))))
    (cons verifier (emcp-util-pkce-challenge verifier))))

(defun emcp-util-random-token ()
  "Return a random URL-safe token (used for OAuth state)."
  (emcp-util-base64url (emcp-util-random-bytes 24)))

;;;; HTTP header value encoding (spec: Streamable HTTP Value Encoding)

(defun emcp-util-token-p (s)
  "Non-nil if S is a valid HTTP field-name token (RFC 9110 tchar)."
  (and (stringp s) (> (length s) 0)
       (string-match-p "\\`[-!#$%&'*+.^_`|~0-9A-Za-z]+\\'" s)))

(defun emcp-util--header-plain-p (s)
  "Non-nil if S can travel as a plain ASCII header value."
  (and (string-match-p "\\`[\x21-\x7e\x20\x09]*\\'" s)
       (not (string-match-p "\\`[ \t]" s))
       (not (string-match-p "[ \t]\\'" s))))

(defun emcp-util--sentinel-p (s)
  "Non-nil if S itself matches the =?base64?...?= sentinel pattern."
  (and (string-prefix-p "=?base64?" s) (string-suffix-p "?=" s)))

(defun emcp-util-encode-header-value (s)
  "Encode S for use as an Mcp-Name / Mcp-Param-* header value."
  (if (and (emcp-util--header-plain-p s)
           (not (emcp-util--sentinel-p s)))
      s
    (concat "=?base64?"
            (base64-encode-string (encode-coding-string s 'utf-8) t)
            "?=")))

(defun emcp-util-param-to-string (v)
  "Convert a primitive tool-parameter value V to its header string form."
  (cond ((stringp v) v)
        ((integerp v) (number-to-string v))
        ((eq v t) "true")
        ((eq v :false) "false")
        (t (signal 'emcp-error
                   (list "Non-primitive value for header parameter" v)))))

;;;; WWW-Authenticate parsing

(defun emcp-util-parse-www-authenticate (value)
  "Parse a WWW-Authenticate header VALUE.
Return a plist (:scheme SCHEME :params ALIST) for the first challenge,
where ALIST maps downcased parameter-name strings to values."
  (when (and value (string-match "\\`\\s-*\\([A-Za-z0-9_-]+\\)" value))
    (let ((scheme (match-string 1 value))
          (pos (match-end 1))
          (params nil))
      (while (string-match
              "\\([A-Za-z0-9_-]+\\)\\s-*=\\s-*\\(?:\"\\([^\"]*\\)\"\\|\\([^,\" \t]+\\)\\)"
              value pos)
        (setq pos (match-end 0))
        (push (cons (downcase (match-string 1 value))
                    (or (match-string 2 value) (match-string 3 value)))
              params))
      (list :scheme scheme :params (nreverse params)))))

;;;; HTTP response head parsing

(defun emcp-util-parse-http-head (text)
  "Parse HTTP response head from TEXT, skipping 1xx interim responses.
Return (STATUS HEADERS BODY-START) or nil if the head is incomplete.
HEADERS is an alist of downcased header-name strings to values."
  (let ((pos 0) result)
    (while (and (not result) pos)
      (let ((head-end (string-search "\r\n\r\n" text pos)))
        (if (null head-end)
            (setq pos nil)                      ; incomplete
          (let ((head (substring text pos head-end)))
            (unless (string-match "\\`HTTP/[0-9.]+ +\\([0-9]+\\)" head)
              (signal 'emcp-http-error (list "Malformed status line" head)))
            (let ((status (string-to-number (match-string 1 head))))
              (if (and (>= status 100) (< status 200))
                  (setq pos (+ head-end 4))     ; skip interim response
                (let ((headers nil))
                  (dolist (line (cdr (split-string head "\r\n")))
                    (when (string-match "\\`\\([^:]+\\):[ \t]*\\(.*\\)\\'" line)
                      (push (cons (downcase (match-string 1 line))
                                  (match-string 2 line))
                            headers)))
                  (setq result (list status (nreverse headers)
                                     (+ head-end 4))))))))))
    result))

(defun emcp-util-header (headers name)
  "Get downcased header NAME from HEADERS alist."
  (cdr (assoc (downcase name) headers)))

;;;; Incremental SSE parser

(defun emcp-util-make-sse-parser ()
  "Return an incremental SSE parser closure.
Call it as (PARSER CHUNK EMIT); EMIT receives a plist
\(:event TYPE :data DATA :id ID) per complete event."
  (let ((buf "") (event nil) (data nil) (id nil))
    (lambda (chunk emit)
      (setq buf (concat buf chunk))
      (let (nl)
        (while (setq nl (string-search "\n" buf))
          (let ((line (substring buf 0 nl)))
            (setq buf (substring buf (1+ nl)))
            (when (string-suffix-p "\r" line)
              (setq line (substring line 0 -1)))
            (cond
             ((string-empty-p line)
              (when data
                (funcall emit (list :event (or event "message")
                                   :data (mapconcat #'identity
                                                    (nreverse data) "\n")
                                   :id id)))
              (setq event nil data nil))
             ((string-prefix-p ":" line))       ; comment / keep-alive
             (t
              (let* ((colon (string-search ":" line))
                     (field (if colon (substring line 0 colon) line))
                     (value (if colon (substring line (1+ colon)) "")))
                (when (string-prefix-p " " value)
                  (setq value (substring value 1)))
                (pcase field
                  ("event" (setq event value))
                  ("data" (push value data))
                  ("id" (setq id value))))))))))))

;;;; Canonical resource URI (RFC 8707 / RFC 9728)

(defun emcp-util-canonical-resource (url)
  "Return the canonical resource URI for MCP server URL."
  (let* ((u (url-generic-parse-url url))
         (scheme (downcase (or (url-type u) "https")))
         (host (downcase (or (url-host u) "")))
         (port (url-portspec u))
         (default-port (pcase scheme ("https" 443) ("http" 80) (_ nil)))
         (path (car (url-path-and-query u))))
    (when (and port default-port (= port default-port))
      (setq port nil))
    (when (and path (string-suffix-p "/" path) (> (length path) 1))
      (setq path (substring path 0 -1)))
    (when (equal path "/") (setq path ""))
    (concat scheme "://" host
            (if port (format ":%d" port) "")
            (or path ""))))

;;;; Form encoding / query parsing

(defun emcp-util-form-encode (alist)
  "Encode ALIST of (NAME . VALUE) strings as application/x-www-form-urlencoded."
  (mapconcat (lambda (kv)
               (concat (url-hexify-string (car kv)) "="
                       (url-hexify-string (cdr kv))))
             alist "&"))

(defun emcp-util-query-parse (query)
  "Parse QUERY string into an alist of (NAME . VALUE) strings."
  (delq nil
        (mapcar (lambda (pair)
                  (when (string-match "\\`\\([^=]*\\)=?\\(.*\\)\\'" pair)
                    (cons (url-unhex-string
                           (replace-regexp-in-string "\\+" " "
                                                     (match-string 1 pair)))
                          (url-unhex-string
                           (replace-regexp-in-string "\\+" " "
                                                     (match-string 2 pair))))))
                (split-string (or query "") "&" t))))

;;;; x-mcp-header schema walking (spec: Custom Headers from Tool Parameters)

(defconst emcp-util--schema-single-keys
  '(items additionalProperties not if then else contains propertyNames)
  "Schema keys whose value is a single subschema (impure reachability).")

(defconst emcp-util--schema-list-keys
  '(oneOf anyOf allOf prefixItems)
  "Schema keys whose value is a list of subschemas (impure reachability).")

(defconst emcp-util--schema-map-keys
  '(patternProperties $defs definitions)
  "Schema keys whose value is a map of subschemas (impure reachability).")

(defun emcp-util--walk-schema (schema pure path collect)
  "Walk SCHEMA collecting x-mcp-header annotations via COLLECT.
PURE is non-nil while reachable only through `properties' chains;
PATH is the list of property-name symbols leading here."
  (when (and schema (listp schema))
    (let ((ann (cdr (assq 'x-mcp-header schema))))
      (when ann (funcall collect ann schema path pure)))
    (dolist (entry (cdr (assq 'properties schema)))
      (when (consp entry)
        (emcp-util--walk-schema (cdr entry) pure
                                (append path (list (car entry))) collect)))
    (dolist (key emcp-util--schema-single-keys)
      (let ((sub (cdr (assq key schema))))
        (when (and sub (listp sub))
          (emcp-util--walk-schema sub nil nil collect))))
    (dolist (key emcp-util--schema-list-keys)
      (dolist (sub (cdr (assq key schema)))
        (when (listp sub) (emcp-util--walk-schema sub nil nil collect))))
    (dolist (key emcp-util--schema-map-keys)
      (dolist (entry (cdr (assq key schema)))
        (when (and (consp entry) (listp (cdr entry)))
          (emcp-util--walk-schema (cdr entry) nil nil collect))))))

(defun emcp-util-tool-header-map (tool)
  "Return alist of (HEADER-NAME . PROPERTY-PATH) for TOOL's x-mcp-header params.
HEADER-NAME is the annotation value (string); PROPERTY-PATH is a list of
property-name symbols.  Signal `emcp-invalid-tool' if any annotation
violates the spec's constraints."
  (let ((schema (cdr (assq 'inputSchema tool)))
        (seen nil) (out nil))
    (emcp-util--walk-schema
     schema t nil
     (lambda (name node path pure)
       (unless pure
         (signal 'emcp-invalid-tool
                 (list "x-mcp-header not statically reachable" name)))
       (unless (emcp-util-token-p name)
         (signal 'emcp-invalid-tool
                 (list "x-mcp-header value is not a valid token" name)))
       (let ((type (cdr (assq 'type node))))
         (unless (member type '("string" "integer" "boolean"))
           (signal 'emcp-invalid-tool
                   (list "x-mcp-header on non-primitive parameter" name type))))
       (let ((key (downcase name)))
         (when (member key seen)
           (signal 'emcp-invalid-tool
                   (list "duplicate x-mcp-header value" name)))
         (push key seen))
       (push (cons name path) out)))
    (nreverse out)))

(defun emcp-util-arguments-ref (arguments path)
  "Look up PATH (list of property-name symbols) in tool ARGUMENTS.
ARGUMENTS may be an alist with symbol keys or a hash table with
string or symbol keys.  Return nil when absent."
  (let ((obj arguments))
    (dolist (key path obj)
      (setq obj
            (cond ((hash-table-p obj)
                   (or (gethash (symbol-name key) obj)
                       (gethash key obj)))
                  ((listp obj) (cdr (assq key obj)))
                  (t nil))))))

(defun emcp-util-param-headers (tool arguments)
  "Return alist of (\"Mcp-Param-NAME\" . ENCODED-VALUE) for TOOL and ARGUMENTS."
  (delq nil
        (mapcar (lambda (entry)
                  (let ((value (emcp-util-arguments-ref arguments (cdr entry))))
                    (when (and value (not (eq value :null)))
                      (cons (concat "Mcp-Param-" (car entry))
                            (emcp-util-encode-header-value
                             (emcp-util-param-to-string value))))))
                (emcp-util-tool-header-map tool))))

;;;; OAuth iss validation (RFC 9207 matrix)

(defun emcp-util-validate-iss (iss expected-issuer advertised)
  "Validate authorization-response ISS against EXPECTED-ISSUER.
ADVERTISED is the AS metadata `authorization_response_iss_parameter_supported'.
Return t when the response may be accepted, nil when it must be rejected."
  (cond ((and iss (string= iss expected-issuer)) t)
        (iss nil)                               ; present but mismatched
        (advertised nil)                        ; advertised but absent
        (t t)))                                 ; absent, not advertised

(provide 'emcp-util)
;;; emcp-util.el ends here
