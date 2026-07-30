(ns btc-crypto.signature
  "Bitcoin-specific strict-DER and sighash-byte handling around the shared
  secp256k1 curve verifier."
  (:require [eth-crypto.core :as eth]))

(def sighash-all 1)
(def sighash-none 2)
(def sighash-single 3)
(def sighash-anyonecanpay 0x80)

(defn- unsigned-byte [value] (bit-and value 0xff))

(defn- minimally-encoded-positive-integer?
  [signature start length]
  (and (pos? length)
       (<= (+ start length) (count signature))
       (zero? (bit-and 0x80
                       (unsigned-byte (nth signature start))))
       (or (= length 1)
           (not
            (and (zero? (unsigned-byte (nth signature start)))
                 (zero?
                  (bit-and
                   0x80
                   (unsigned-byte (nth signature (inc start))))))))))

(defn strict-der?
  "Bitcoin Core IsValidSignatureEncoding for a DER signature plus its final
  one-byte sighash type."
  [signature]
  (let [signature (vec signature)
        size (count signature)]
    (if-not (<= 9 size 73)
      false
      (let [r-length (unsigned-byte (nth signature 3))
            s-marker (+ 4 r-length)]
        (if-not (< (inc s-marker) (dec size))
          false
          (let [s-length (unsigned-byte (nth signature (inc s-marker)))
                s-start (+ s-marker 2)]
            (boolean
             (and (= 0x30 (unsigned-byte (nth signature 0)))
                  (= (- size 3) (unsigned-byte (nth signature 1)))
                  (= 0x02 (unsigned-byte (nth signature 2)))
                  (minimally-encoded-positive-integer?
                   signature 4 r-length)
                  (= 0x02 (unsigned-byte (nth signature s-marker)))
                  (= (+ r-length s-length 7) size)
                  (minimally-encoded-positive-integer?
                   signature s-start s-length)))))))))

(defn defined-sighash-type?
  [hash-type]
  (contains? #{sighash-all sighash-none sighash-single}
             (bit-and (unsigned-byte hash-type) 0x1f)))

(defn- bytes->integer [bytes]
  #?(:clj
     (java.math.BigInteger.
      1 (byte-array (map unchecked-byte bytes)))
     :cljs
     (reduce (fn [result byte]
               (+ (* result (js/BigInt 256))
                  (js/BigInt (unsigned-byte byte))))
             (js/BigInt 0) bytes)))

(defn parse-strict-der
  "Return {:r :s :sighash-type} or nil. Empty signatures are ordinary
  CHECKSIG false values and are not DER errors in Bitcoin Script."
  [signature]
  (when (strict-der? signature)
    (let [signature (vec signature)
          r-length (unsigned-byte (nth signature 3))
          r-start 4
          s-length (unsigned-byte (nth signature (+ 5 r-length)))
          s-start (+ 6 r-length)]
      {:r (bytes->integer
           (subvec signature r-start (+ r-start r-length)))
       :s (bytes->integer
           (subvec signature s-start (+ s-start s-length)))
       :sighash-type (unsigned-byte (peek signature))})))

(defn low-s?
  [signature]
  (boolean
   (when-let [{:keys [s]} (parse-strict-der signature)]
     (eth/secp256k1-low-s? s))))

(defn verify-der
  "Verify a strict-DER Bitcoin signature over an already-computed digest.
  `:low-s?` and `:defined-sighash?` are explicit caller flags because their
  activation/policy differs from raw ECDSA validity."
  ([digest signature pubkey]
   (verify-der digest signature pubkey {}))
  ([digest signature pubkey
    {:keys [low-s? defined-sighash?]
     :or {low-s? false defined-sighash? false}}]
   (boolean
    (when-let [{:keys [r s sighash-type]}
               (parse-strict-der signature)]
      (and (or (not low-s?) (eth/secp256k1-low-s? s))
           (or (not defined-sighash?)
               (defined-sighash-type? sighash-type))
           (eth/secp256k1-verify digest {:r r :s s} pubkey))))))
