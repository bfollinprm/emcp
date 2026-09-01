;;; emcp-test.el --- Unit tests for emcp  -*- lexical-binding: t; -*-

;;; Commentary:
;; Pure-function unit tests: PKCE, header value encoding, SSE parsing,
;; HTTP head parsing, WWW-Authenticate parsing, x-mcp-header schema
;; validation and extraction, canonical resource URIs, iss validation.

;;; Code:

(require 'ert)
(require 'emcp-util)
(require 'emcp)

;;;; PKCE / base64url

(ert-deftest emcp-test-pkce-rfc7636-vector ()
  "S256 challenge matches the RFC 7636 appendix B test vector."
  (should (equal (emcp-util-pkce-challenge
                  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                 "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")))

(ert-deftest emcp-test-pkce-pair-shape ()
  (let ((pair (emcp-util-pkce-pair)))
    (should (= 43 (length (car pair))))
    (should (= 43 (length (cdr pair))))
    (should-not (string-match-p "[+/=]" (car pair)))
    (should (equal (cdr pair) (emcp-util-pkce-challenge (car pair))))))

(ert-deftest emcp-test-base64url ()
  (should (equal (emcp-util-base64url "\xfb\xff") "-_8"))
  (should (equal (emcp-util-base64url "ab") "YWI")))

;;;; Header value encoding (spec Value Encoding examples)

(ert-deftest emcp-test-header-encoding-plain ()
  (should (equal (emcp-util-encode-header-value "us-west1") "us-west1")))

(ert-deftest emcp-test-header-encoding-non-ascii ()
  (should (equal (emcp-util-encode-header-value "Hello, 世界")
                 "=?base64?SGVsbG8sIOS4lueVjA==?=")))

(ert-deftest emcp-test-header-encoding-padded ()
  (should (equal (emcp-util-encode-header-value " padded ")
                 "=?base64?IHBhZGRlZCA=?=")))

(ert-deftest emcp-test-header-encoding-newline ()
  (should (equal (emcp-util-encode-header-value "line1\nline2")
                 "=?base64?bGluZTEKbGluZTI=?=")))

(ert-deftest emcp-test-header-encoding-sentinel-literal ()
  (should (equal (emcp-util-encode-header-value "=?base64?literal?=")
                 "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=")))

(ert-deftest emcp-test-param-to-string ()
  (should (equal (emcp-util-param-to-string 42) "42"))
  (should (equal (emcp-util-param-to-string -7) "-7"))
  (should (equal (emcp-util-param-to-string t) "true"))
  (should (equal (emcp-util-param-to-string :false) "false"))
  (should (equal (emcp-util-param-to-string "x") "x"))
  (should-error (emcp-util-param-to-string 4.2) :type 'emcp-error))

(ert-deftest emcp-test-token-p ()
  (should (emcp-util-token-p "Region"))
  (should (emcp-util-token-p "x-y.z~1"))
  (should-not (emcp-util-token-p ""))
  (should-not (emcp-util-token-p "a b"))
  (should-not (emcp-util-token-p "a\nb"))
  (should-not (emcp-util-token-p "a:b")))

;;;; WWW-Authenticate

(ert-deftest emcp-test-www-authenticate ()
  (let ((parsed (emcp-util-parse-www-authenticate
                 (concat "Bearer resource_metadata="
                         "\"https://mcp.example.com/.well-known/oauth-protected-resource\","
                         " scope=\"files:read files:write\", error=\"insufficient_scope\""))))
    (should (equal (plist-get parsed :scheme) "Bearer"))
    (should (equal (cdr (assoc "resource_metadata" (plist-get parsed :params)))
                   "https://mcp.example.com/.well-known/oauth-protected-resource"))
    (should (equal (cdr (assoc "scope" (plist-get parsed :params)))
                   "files:read files:write"))
    (should (equal (cdr (assoc "error" (plist-get parsed :params)))
                   "insufficient_scope"))))

(ert-deftest emcp-test-www-authenticate-nil ()
  (should-not (emcp-util-parse-www-authenticate nil)))

;;;; SSE parser

(ert-deftest emcp-test-sse-basic ()
  (let ((parser (emcp-util-make-sse-parser))
        (events nil))
    (funcall parser "data: hello\r\n\r\nevent: endpoint\ndata: /msg\n\n"
             (lambda (e) (push e events)))
    (setq events (nreverse events))
    (should (= 2 (length events)))
    (should (equal (plist-get (car events) :event) "message"))
    (should (equal (plist-get (car events) :data) "hello"))
    (should (equal (plist-get (cadr events) :event) "endpoint"))
    (should (equal (plist-get (cadr events) :data) "/msg"))))

(ert-deftest emcp-test-sse-chunked-multiline ()
  (let* ((parser (emcp-util-make-sse-parser))
         (events nil)
         (emit (lambda (e) (push e events))))
    (funcall parser ": keep-alive\ndata: line1\nda" emit)
    (should (null events))
    (funcall parser "ta: line2\n\n" emit)
    (should (= 1 (length events)))
    (should (equal (plist-get (car events) :data) "line1\nline2"))))

(ert-deftest emcp-test-sse-comment-only-no-event ()
  (let ((parser (emcp-util-make-sse-parser))
        (events nil))
    (funcall parser ":\r\n\r\n" (lambda (e) (push e events)))
    (should (null events))))

;;;; HTTP head parsing

(ert-deftest emcp-test-http-head-simple ()
  (cl-destructuring-bind (status headers body-start)
      (emcp-util-parse-http-head
       "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: abc\r\n\r\n{}")
    (should (= status 200))
    (should (equal (emcp-util-header headers "content-type")
                   "application/json"))
    (should (equal (emcp-util-header headers "MCP-SESSION-ID") "abc"))
    (should (equal (substring
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: abc\r\n\r\n{}"
                    body-start)
                   "{}"))))

(ert-deftest emcp-test-http-head-skips-1xx ()
  (cl-destructuring-bind (status _headers _body-start)
      (emcp-util-parse-http-head
       "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n")
    (should (= status 401))))

(ert-deftest emcp-test-http-head-incomplete ()
  (should-not (emcp-util-parse-http-head "HTTP/1.1 200 OK\r\nContent-")))

;;;; Canonical resource URI

(ert-deftest emcp-test-canonical-resource ()
  (should (equal (emcp-util-canonical-resource "https://MCP.Example.COM/mcp")
                 "https://mcp.example.com/mcp"))
  (should (equal (emcp-util-canonical-resource "https://mcp.example.com:443/mcp/")
                 "https://mcp.example.com/mcp"))
  (should (equal (emcp-util-canonical-resource "https://mcp.example.com:8443")
                 "https://mcp.example.com:8443"))
  (should (equal (emcp-util-canonical-resource "https://mcp.example.com/#frag")
                 "https://mcp.example.com"))
  (should (equal (emcp-util-canonical-resource "http://localhost:8080/server/mcp")
                 "http://localhost:8080/server/mcp")))

;;;; Form encode / query parse

(ert-deftest emcp-test-form-roundtrip ()
  (let* ((alist '(("resource" . "https://mcp.example.com/mcp")
                  ("scope" . "files:read files:write")))
         (encoded (emcp-util-form-encode alist)))
    (should-not (string-match-p " " encoded))
    (should (equal (emcp-util-query-parse encoded) alist))))

;;;; x-mcp-header schema handling

(defun emcp-test--tool (schema)
  `((name . "t") (inputSchema . ,schema)))

(ert-deftest emcp-test-tool-headers-valid ()
  (let ((map (emcp-util-tool-header-map
              (emcp-test--tool
               '((type . "object")
                 (properties
                  . ((region . ((type . "string") (x-mcp-header . "Region")))
                     (nested
                      . ((type . "object")
                         (properties
                          . ((count . ((type . "integer")
                                       (x-mcp-header . "Count"))))))))))))))
    (should (equal (assoc "Region" map) '("Region" . (region))))
    (should (equal (assoc "Count" map) '("Count" . (nested count))))))

(ert-deftest emcp-test-tool-headers-reject-number-type ()
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (properties
                     . ((n . ((type . "number") (x-mcp-header . "N"))))))))
                :type 'emcp-invalid-tool))

(ert-deftest emcp-test-tool-headers-reject-under-oneof ()
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (oneOf . (((type . "object")
                               (properties
                                . ((a . ((type . "string")
                                         (x-mcp-header . "A")))))))))))
                :type 'emcp-invalid-tool))

(ert-deftest emcp-test-tool-headers-reject-under-items ()
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (properties
                     . ((arr . ((type . "array")
                                (items . ((type . "string")
                                          (x-mcp-header . "Item"))))))))))
                :type 'emcp-invalid-tool))

(ert-deftest emcp-test-tool-headers-reject-duplicate-case-insensitive ()
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (properties
                     . ((a . ((type . "string") (x-mcp-header . "Region")))
                        (b . ((type . "string") (x-mcp-header . "region"))))))))
                :type 'emcp-invalid-tool))

(ert-deftest emcp-test-tool-headers-reject-bad-name ()
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (properties
                     . ((a . ((type . "string") (x-mcp-header . "bad name"))))))))
                :type 'emcp-invalid-tool)
  (should-error (emcp-util-tool-header-map
                 (emcp-test--tool
                  '((type . "object")
                    (properties
                     . ((a . ((type . "string") (x-mcp-header . ""))))))))
                :type 'emcp-invalid-tool))

(ert-deftest emcp-test-param-headers-extraction ()
  (let* ((tool (emcp-test--tool
                '((type . "object")
                  (properties
                   . ((region . ((type . "string") (x-mcp-header . "Region")))
                      (flag . ((type . "boolean") (x-mcp-header . "Flag")))
                      (count . ((type . "integer") (x-mcp-header . "Count")))
                      (skip . ((type . "string") (x-mcp-header . "Skip"))))))))
         (headers (emcp-util-param-headers
                   tool
                   '((region . "us-west1") (flag . :false) (count . 42)))))
    (should (equal (cdr (assoc "Mcp-Param-Region" headers)) "us-west1"))
    (should (equal (cdr (assoc "Mcp-Param-Flag" headers)) "false"))
    (should (equal (cdr (assoc "Mcp-Param-Count" headers)) "42"))
    (should-not (assoc "Mcp-Param-Skip" headers))))

(ert-deftest emcp-test-param-headers-hash-arguments ()
  (let ((tool (emcp-test--tool
               '((type . "object")
                 (properties
                  . ((region . ((type . "string") (x-mcp-header . "Region"))))))))
        (arguments (make-hash-table :test 'equal)))
    (puthash "region" "Hello, 世界" arguments)
    (should (equal (cdr (assoc "Mcp-Param-Region"
                               (emcp-util-param-headers tool arguments)))
                   "=?base64?SGVsbG8sIOS4lueVjA==?="))))

;;;; iss validation (RFC 9207 matrix)

(ert-deftest emcp-test-validate-iss ()
  (let ((issuer "https://as.example.com"))
    ;; advertised + present matching -> ok
    (should (emcp-util-validate-iss issuer issuer t))
    ;; advertised + absent -> reject
    (should-not (emcp-util-validate-iss nil issuer t))
    ;; not advertised + present matching -> ok (compared anyway)
    (should (emcp-util-validate-iss issuer issuer nil))
    ;; not advertised + present mismatched -> reject
    (should-not (emcp-util-validate-iss "https://evil.example.com" issuer nil))
    ;; not advertised + absent -> proceed
    (should (emcp-util-validate-iss nil issuer nil))
    ;; exact string comparison: no normalization
    (should-not (emcp-util-validate-iss "https://AS.example.com" issuer nil))))

;;;; JSON helpers

(ert-deftest emcp-test-json-roundtrip ()
  (let ((obj (emcp-obj 'a 1 'b "x" 'c :false 'nested (emcp-obj 'd t)
                       'arr (vector 1 2))))
    (should (equal (emcp-util-json-parse (emcp-util-json-serialize obj))
                   '((a . 1) (b . "x") (c . :false)
                     (nested . ((d . t))) (arr . (1 2)))))))

(ert-deftest emcp-test-obj-drops-nil ()
  (should (equal (emcp-obj 'a 1 'b nil 'c 2) '((a . 1) (c . 2)))))

(ert-deftest emcp-test-get-normalizes-null ()
  "JSON null must read as absent (regression: nextCursor null loop)."
  (let ((parsed (emcp-util-json-parse
                 "{\"nextCursor\": null, \"a\": {\"b\": null}}")))
    (should-not (emcp-get parsed 'nextCursor))
    (should-not (emcp-get parsed 'a 'b))
    (should-not (emcp-get parsed 'missing))))

(ert-deftest emcp-test-curl-config-rejects-crlf ()
  "Header values with CR/LF must be refused (header injection)."
  (should-error (emcp-curl--config-file '(("Authorization" . "Bearer x\r\nHost: evil")))
                :type 'emcp-error)
  (should-error (emcp-curl--config-file '(("Bad\nName" . "v")))
                :type 'emcp-error)
  (let ((file (emcp-curl--config-file '(("Authorization" . "Bearer \"q\"")))))
    (unwind-protect
        (with-temp-buffer
          (insert-file-contents file)
          (should (equal (buffer-string)
                         "header = \"Authorization: Bearer \\\"q\\\"\"\n")))
      (delete-file file))))

(ert-deftest emcp-test-empty-object-serializes ()
  (should (equal (emcp-util-json-serialize emcp-util-empty-object) "{}")))

;;;; _meta injection

(ert-deftest emcp-test-wrap-params-modern ()
  (let* ((conn (emcp--make-connection :era 'modern
                                      :protocol-version emcp-protocol-version))
         (wrapped (emcp--wrap-params conn (emcp-obj 'name "tool")))
         (json (emcp-util-json-parse (emcp-util-json-serialize wrapped)))
         (meta (emcp-get json '_meta)))
    (should (equal (cdr (assq (intern "io.modelcontextprotocol/protocolVersion")
                              meta))
                   "2026-07-28"))
    (should (equal (emcp-get (cdr (assq (intern "io.modelcontextprotocol/clientInfo")
                                        meta))
                             'name)
                   "emcp"))
    (should (assq (intern "io.modelcontextprotocol/clientCapabilities") meta))
    (should (equal (emcp-get json 'name) "tool"))))

(ert-deftest emcp-test-wrap-params-legacy-untouched ()
  (let ((conn (emcp--make-connection :era 'legacy
                                     :protocol-version "2025-06-18")))
    (should (equal (emcp--wrap-params conn '((name . "x"))) '((name . "x"))))))

;;;; AS discovery URL construction

(ert-deftest emcp-test-as-metadata-urls-with-path ()
  (should (equal (emcp-oauth--as-metadata-urls "https://auth.example.com/tenant1")
                 '("https://auth.example.com/.well-known/oauth-authorization-server/tenant1"
                   "https://auth.example.com/.well-known/openid-configuration/tenant1"
                   "https://auth.example.com/tenant1/.well-known/openid-configuration"))))

(ert-deftest emcp-test-as-metadata-urls-without-path ()
  (should (equal (emcp-oauth--as-metadata-urls "https://auth.example.com")
                 '("https://auth.example.com/.well-known/oauth-authorization-server"
                   "https://auth.example.com/.well-known/openid-configuration"))))

(ert-deftest emcp-test-prm-well-known-urls ()
  (should (equal (emcp-oauth--well-known-prm-urls "https://example.com/public/mcp")
                 '("https://example.com/.well-known/oauth-protected-resource/public/mcp"
                   "https://example.com/.well-known/oauth-protected-resource")))
  (should (equal (emcp-oauth--well-known-prm-urls "https://example.com")
                 '("https://example.com/.well-known/oauth-protected-resource"))))

(provide 'emcp-test)
;;; emcp-test.el ends here
