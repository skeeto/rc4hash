;;; rc4hash.el --- RC4 salted crypto hash function -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; The two primary entrypoints:

;; * `rc4hash'        : produces a unique, salted hash of a password
;; * `rc4hash-verify' : validates a hash produces by `rc4hash'

;;; Code:

(require 'cl-lib)
(require 'ucs-normalize)

(cl-defstruct (rc4 (:constructor rc4-create))
  "Full RC4 cipher state."
  (state (apply #'unibyte-string (number-sequence 0 255)))
  (i 0) (j 0))

(defun rc4--swap (rc4 i j)
  "Swap bytes at positions I and J in RC4's state."
  (let ((temp (aref (rc4-state rc4) i)))
    (setf (aref (rc4-state rc4) i) (aref (rc4-state rc4) j)
          (aref (rc4-state rc4) j) temp)))

(defun rc4-mix (rc4 key)
  "Mix arbitrary-length KEY into RC4's state. KEY will be treated
as UTF-8 if multibyte."
  (let* ((j 0)
         (ukey (string-as-unibyte key))
         (length (length ukey))
         (subkeys (cl-loop for i from 0 below length by (+ i 256)
                           collect (substring ukey i (min length (+ i 256))))))
    (prog1 rc4
      (dolist (subkey subkeys)
        (dotimes (i 256)
          (setq j (% (+ j (aref (rc4-state rc4) i)
                        (aref subkey (% i (length subkey)))) 256))
          (rc4--swap rc4 i j))))))

(defun rc4-emit (rc4)
  "Generate a single byte from RC4."
  (let ((state (rc4-state rc4)))
    (setf (rc4-i rc4) (% (+ (rc4-i rc4) 1) 256)
          (rc4-j rc4) (% (+ (rc4-j rc4) (aref state (rc4-i rc4))) 256))
    (let ((i (rc4-i rc4))
          (j (rc4-j rc4)))
      (rc4--swap rc4 i j)
      (aref state (% (+ (aref state i) (aref state j)) 256)))))

(defun rc4-emit-n (rc4 n)
  "Emit N bytes of output from RC4 as a unibyte string."
  (let ((output (make-string n 0)))
    (prog1 output
      (dotimes (i n)
        (setf (aref output i) (rc4-emit rc4))))))

(defun rc4hash-salt ()
  "Produce a random salt from a high-quality source."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (call-process "head" "/dev/urandom" (current-buffer)
                  nil "-c" (number-to-string 4))
    (buffer-string)))

(cl-defun rc4hash (password &optional (difficulty 262143) (salt (rc4hash-salt)))
  "Produce a salted RC4 hash for PASSWORD, using DIFFICULTY factor, and SALT.
The higher the difficulty, the greater the time the hash takes to
compute and verify."
  (let ((rc4 (rc4-create))
        (upassword (string-as-unibyte (ucs-normalize-NFC-string password))))
    (rc4-mix rc4 salt)
    (let* ((padsize (- 256 (length upassword)))
           (key (concat upassword (rc4-emit-n rc4 padsize))))
      (dotimes (_ (1+ difficulty))
        (rc4-mix rc4 key)))
    (cl-loop repeat (* difficulty 64) do (rc4-emit rc4))
    (concat salt (rc4hash-encode-uint32 difficulty) (rc4-emit-n rc4 20))))

(defun rc4hash-encode-uint32 (x)
  "Encode integer X as a 4-element unibyte string."
  (unibyte-string
   (logand (lsh x -24) #xff)
   (logand (lsh x -16) #xff)
   (logand (lsh x  -8) #xff)
   (logand (lsh x   0) #xff)))

(defun rc4hash-decode-uint32 (string)
  "Decode an integer from a 4-element unibyte string."
  (+ (lsh (aref string 0) 24)
     (lsh (aref string 1) 16)
     (lsh (aref string 2) 8)
     (lsh (aref string 3) 0)))

(defun rc4hash-to-hex (hash)
  "Convert unibyte string HASH to a string of hexidecimal digits."
  (let ((output (make-string (* 2 (length hash)) 0)))
    (prog1 output
      (dotimes (i (length hash))
        (let ((byte (format "%02x" (aref hash i))))
          (setf (aref output (+ 0 (* i 2))) (aref byte 0)
                (aref output (+ 1 (* i 2))) (aref byte 1)))))))

(defun rc4hash-from-hex (string)
  "Compute STRING of hexidecimal digits to a unibyte string."
  (let ((output (make-string (/ (length string) 2) 0)))
    (prog1 output
      (dotimes (i (/ (length string) 2))
        (let ((digits (substring string (* 2 i) (* 2 (1+ i)))))
          (setf (aref output i) (string-to-number digits 16)))))))

(defun rc4hash-verify (hash password)
  "Verify HASH for given PASSWORD, returning non-nil for valid match."
  (let ((salt (substring hash 0 4))
        (difficulty (rc4hash-decode-uint32 (substring hash 4 8))))
    (string= (rc4hash password difficulty salt) hash)))

(provide 'rc4hash)

;;; rc4hash.el ends here
