(ns btc-crypto.core
  "Bitcoin address/key encoding: SHA256d, HASH160, WIF, and P2PKH/P2WPKH
  address derivation. Reuses eth-crypto's secp256k1 point arithmetic
  (`private->public` — same curve as Ethereum) for the public-key math, and
  kotoba.lang.crypto for SHA-256.

  PORTABILITY: :clj-only (wrapped #?(:clj (do ...)) with throwing :cljs
  stubs of the same names, matching eth-crypto.core's precedent) — its
  ripemd160/base58 deps are themselves :clj-only for the same reason."
  (:require [eth-crypto.core :as eth]
            [btc-crypto.ripemd160 :as ripemd]
            [btc-crypto.base58 :as base58]
            [btc-crypto.bech32 :as bech32]
            [kotoba.lang.crypto :as kc])
  #?(:clj (:import (java.util Arrays))))

#?(:clj
(do

(defn sha256d
  "Double SHA-256 (Bitcoin's block-hash / txid / checksum digest)."
  ^bytes [^bytes data] (kc/hash :sha256 (kc/hash :sha256 data)))

(defn hash160
  "RIPEMD160(SHA256(data)) — Bitcoin's \"HASH160\", used for P2PKH/P2WPKH
  pubkey hashes."
  ^bytes [^bytes data] (ripemd/ripemd160 (kc/hash :sha256 data)))

(defn compressed-pubkey
  "Compressed (33-byte, 0x02/0x03-prefixed) secp256k1 public key for a
  32-byte private key."
  ^bytes [^bytes privkey]
  (let [uncompressed (eth/private->public privkey) ; 64 bytes X(32)||Y(32)
        y-last (aget uncompressed 63)
        prefix (unchecked-byte (if (even? (bit-and (long y-last) 1)) 0x02 0x03))
        out (byte-array 33)]
    (aset-byte out 0 prefix)
    (System/arraycopy uncompressed 0 out 1 32)
    out))

;; ─── WIF (Wallet Import Format) ──────────────────────────────────────────────

(def ^:private WIF-VERSION {:mainnet 0x80 :testnet 0xef})

(defn wif-encode
  "WIF-encode a 32-byte private key. `compressed?` (default true) marks that
  the corresponding public key should be used in compressed form."
  (^String [privkey] (wif-encode privkey :mainnet true))
  (^String [privkey network] (wif-encode privkey network true))
  (^String [^bytes privkey network compressed?]
   (let [version (get WIF-VERSION network)
         suffix (if compressed? [(byte 0x01)] [])
         payload (byte-array (concat [(unchecked-byte version)] (seq privkey) suffix))]
     (base58/encode-check payload))))

(defn wif-decode
  "Decode a WIF string. Returns {:private-key bytes32 :network :mainnet|:testnet
  :compressed? bool}."
  [^String s]
  (let [payload (base58/decode-check s)
        n (alength payload)
        version (bit-and (long (aget payload 0)) 0xff)
        network (some (fn [[k v]] (when (= v version) k)) WIF-VERSION)
        compressed? (and (= n 34) (= 1 (bit-and (long (aget payload 33)) 0xff)))]
    (when (nil? network) (throw (ex-info "wif: unknown version byte" {:version version})))
    (when-not (contains? #{33 34} n) (throw (ex-info "wif: bad payload length" {:len n})))
    {:private-key (Arrays/copyOfRange payload 1 33) :network network :compressed? compressed?}))

;; ─── addresses ────────────────────────────────────────────────────────────

(def ^:private P2PKH-VERSION {:mainnet 0x00 :testnet 0x6f})
(def ^:private HRP {:mainnet "bc" :testnet "tb"})

(defn p2pkh-address
  "Legacy Base58Check P2PKH address for a compressed public key."
  (^String [pubkey] (p2pkh-address pubkey :mainnet))
  (^String [^bytes pubkey network]
   (base58/encode-check
    (byte-array (cons (unchecked-byte (get P2PKH-VERSION network)) (seq (hash160 pubkey)))))))

(defn p2wpkh-address
  "Native SegWit v0 (bech32) P2WPKH address for a compressed public key."
  (^String [pubkey] (p2wpkh-address pubkey :mainnet))
  (^String [^bytes pubkey network]
   (bech32/encode-segwit-address (get HRP network) 0 (seq (hash160 pubkey)))))

(defn address-of-privkey
  "{:p2pkh .. :p2wpkh ..} addresses for a 32-byte private key."
  ([privkey] (address-of-privkey privkey :mainnet))
  ([privkey network]
   (let [pubkey (compressed-pubkey privkey)]
     {:p2pkh (p2pkh-address pubkey network) :p2wpkh (p2wpkh-address pubkey network)})))

) ;; end do
:cljs
(do
  (defn sha256d [& _] (throw (ex-info "btc-crypto.core/sha256d is :clj-only" {})))
  (defn hash160 [& _] (throw (ex-info "btc-crypto.core/hash160 is :clj-only (btc-crypto.ripemd160)" {})))
  (defn compressed-pubkey [& _] (throw (ex-info "btc-crypto.core/compressed-pubkey is :clj-only" {})))
  (defn wif-encode [& _] (throw (ex-info "btc-crypto.core/wif-encode is :clj-only (btc-crypto.base58)" {})))
  (defn wif-decode [& _] (throw (ex-info "btc-crypto.core/wif-decode is :clj-only (btc-crypto.base58)" {})))
  (defn p2pkh-address [& _] (throw (ex-info "btc-crypto.core/p2pkh-address is :clj-only (btc-crypto.base58)" {})))
  (defn p2wpkh-address [& _] (throw (ex-info "btc-crypto.core/p2wpkh-address is :clj-only" {})))
  (defn address-of-privkey [& _] (throw (ex-info "btc-crypto.core/address-of-privkey is :clj-only" {})))))
