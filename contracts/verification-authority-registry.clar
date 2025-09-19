;; verification-authority-registry
;; Registry for trusted verification authorities

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u2001))
(define-constant ERR_AUTHORITY_NOT_FOUND (err u2002))

;; Data Variables
(define-data-var authority-counter uint u0)

;; Data Maps
(define-map authorities uint {
    authority: principal,
    name: (string-ascii 100),
    authorized: bool,
    credentials-issued: uint,
    added-at: uint
})

(define-map authority-principals principal uint)

;; Public Functions
(define-public (register-authority (authority principal) (name (string-ascii 100)))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (let ((authority-id (+ (var-get authority-counter) u1)))
            (map-set authorities authority-id {
                authority: authority,
                name: name,
                authorized: true,
                credentials-issued: u0,
                added-at: burn-block-height
            })
            (map-set authority-principals authority authority-id)
            (var-set authority-counter authority-id)
            (ok authority-id))))

(define-public (revoke-authority (authority-id uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (match (map-get? authorities authority-id)
            authority (begin
                (map-set authorities authority-id (merge authority {authorized: false}))
                (ok true))
            ERR_AUTHORITY_NOT_FOUND)))

;; Read-only Functions
(define-read-only (get-authority (authority-id uint))
    (map-get? authorities authority-id))

(define-read-only (is-authorized-authority (authority principal))
    (match (map-get? authority-principals authority)
        authority-id (match (map-get? authorities authority-id)
            authority-data (get authorized authority-data)
            false)
        false))

(define-read-only (get-authority-count)
    (var-get authority-counter))