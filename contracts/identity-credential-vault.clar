;; identity-credential-vault
;; Secure credential storage and management for decentralized identity

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u1001))
(define-constant ERR_CREDENTIAL_NOT_FOUND (err u1002))

;; Data Variables
(define-data-var credential-counter uint u0)

;; Data Maps
(define-map credentials uint {
    owner: principal,
    credential-type: (string-ascii 50),
    encrypted-data: (string-ascii 500),
    issued-at: uint,
    expires-at: uint,
    verified: bool
})

;; Public Functions
(define-public (store-credential (credential-type (string-ascii 50)) (encrypted-data (string-ascii 500)) (expires-at uint))
    (let ((credential-id (+ (var-get credential-counter) u1)))
        (map-set credentials credential-id {
            owner: tx-sender,
            credential-type: credential-type,
            encrypted-data: encrypted-data,
            issued-at: burn-block-height,
            expires-at: expires-at,
            verified: false
        })
        (var-set credential-counter credential-id)
        (ok credential-id)))

(define-public (verify-credential (credential-id uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (match (map-get? credentials credential-id)
            credential (begin
                (map-set credentials credential-id (merge credential {verified: true}))
                (ok true))
            ERR_CREDENTIAL_NOT_FOUND)))

;; Read-only Functions
(define-read-only (get-credential (credential-id uint))
    (map-get? credentials credential-id))

(define-read-only (get-credential-count)
    (var-get credential-counter))