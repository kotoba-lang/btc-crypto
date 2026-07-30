(ns btc-crypto.schnorr-test
  (:require [btc-crypto.schnorr :as schnorr]
            [clojure.test :refer [deftest is]]))

(defn hex-bytes [value]
  (mapv #(Integer/parseInt (apply str %) 16) (partition 2 value)))

(deftest official-bip340-vector-zero
  ;; BIP340 test-vectors.csv, vector 0.
  (let [public-key
        (hex-bytes
         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        message
        (hex-bytes
         "0000000000000000000000000000000000000000000000000000000000000000")
        signature
        (hex-bytes
         (str
          "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
          "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"))]
    (is (schnorr/verify message public-key signature))
    (is (false? (schnorr/verify
                 (assoc message 31 1) public-key signature)))
    (is (false? (schnorr/verify message public-key (pop signature))))))
