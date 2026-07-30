(ns btc-crypto.signature-test
  (:require [btc-crypto.core :as btc]
            [btc-crypto.signature :as signature]
            [btc-crypto.tx :as tx]
            [clojure.test :refer [deftest is]]
            [eth-crypto.core :as eth]))

(def private-key
  (byte-array
   (map unchecked-byte
        (range 1 33))))

(deftest strict-der-verification-uses-the-shared-curve-implementation
  (let [digest (btc/sha256d (.getBytes "bitcoin consensus" "UTF-8"))
        signed (eth/secp256k1-sign private-key digest)
        der (tx/der-encode-sig signed)
        bitcoin-signature
        (byte-array
         (concat (seq der) [(unchecked-byte signature/sighash-all)]))
        pubkey (btc/compressed-pubkey private-key)]
    (is (signature/strict-der? bitcoin-signature))
    (is (signature/low-s? bitcoin-signature))
    (is (= signature/sighash-all
           (:sighash-type
            (signature/parse-strict-der bitcoin-signature))))
    (is (signature/verify-der
         digest bitcoin-signature pubkey
         {:low-s? true :defined-sighash? true}))
    (is (false?
         (signature/verify-der
          (assoc (vec digest) 0
                 (bit-xor 1 (bit-and 0xff (aget digest 0))))
          bitcoin-signature pubkey)))))

(deftest malformed-and-undefined-signatures-fail-closed
  (is (false? (signature/strict-der? [])))
  (is (false? (signature/strict-der?
               [0x30 0x06 0x02 0x01 0x80 0x02 0x01 0x01 0x01])))
  (is (false? (signature/strict-der?
               [0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x80 0x01])))
  (is (signature/defined-sighash-type? 0x81))
  (is (false? (signature/defined-sighash-type? 0x04))))
