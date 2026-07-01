# btc-crypto (Bitcoin 暗号・エンコーディング)

Bitcoin 固有の暗号プリミティブとエンコーディングを portable Clojure (`.cljc`) で。
[kotoba-lang/eth-crypto](https://github.com/kotoba-lang/eth-crypto) の secp256k1
点演算・RFC 6979 決定論的 ECDSA（Bitcoin も同じ曲線）と
[kotoba-lang/crypto](https://github.com/kotoba-lang/crypto) の SHA-256 の上に、
Bitcoin 固有の RIPEMD-160・Base58Check・Bech32/Bech32m・BIP-32/39/44・WIF・
アドレス導出・tx 署名を追加する。ADR: `90-docs/adr/2607012200-kotoba-lang-btc-mining-wallet-substrate.md`。

すべての公開関数は既知のテストベクタ（BIP-32 Test vector 1、trezor/python-mnemonic
の BIP-39 vectors.json、BIP-173 の bech32 例、BIP-143 の Native P2WPKH worked
example、privkey=1 の著名なアドレス/WIF、実際の genesis block header）で
**byte-for-byte 検証済み**（`clojure -M:test`、55 assertions green）。

## Namespaces

- `btc-crypto.ripemd160` — RIPEMD-160（JDK には無いため pure 実装）
- `btc-crypto.base58` — Base58 / Base58Check（WIF・legacy アドレスの符号化）
- `btc-crypto.bech32` — Bech32 (BIP-173) / Bech32m (BIP-350)、segwit アドレス
  ⇄ (witver, program)
- `btc-crypto.core` — `sha256d`、`hash160`、`compressed-pubkey`、WIF
  encode/decode、P2PKH/P2WPKH アドレス導出
- `btc-crypto.bip32` — HD 鍵導出（`seed->master`、`ckd-priv`、`derive-path`、
  xprv/xpub `serialize`）。**private-key path のみ**（CKDpub/xpub-only 導出は
  v1 スコープ外 — seed を持つ wallet はそもそも不要）
- `btc-crypto.bip39` — mnemonic ⇄ seed。`mnemonic->seed` は wordlist 不要
  （PBKDF2-HMAC-SHA512 のみ）。`entropy->mnemonic`/`mnemonic->entropy` は
  `resources/bip39/english.txt`（公式 bitcoin/bips のワードリストをそのまま
  同梱、sha256 で読み込み時に検証）が要る
- `btc-crypto.tx` — legacy P2PKH SIGHASH_ALL と BIP-143 P2WPKH SIGHASH_ALL
  の tx 署名（SIGHASH_ALL のみ、P2SH/multisig/Taproot は対象外）

## Quick start

```clojure
(require '[btc-crypto.bip32 :as bip32]
         '[btc-crypto.bip39 :as bip39]
         '[btc-crypto.core :as btc]
         '[clojure.java.io :as io])

(def wordlist (bip39/load-wordlist (slurp (io/resource "bip39/english.txt"))))
(def seed (bip39/mnemonic->seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
(def account (-> (bip32/seed->master seed) (bip32/derive-path "m/84'/0'/0'/0/0")))

(btc/address-of-privkey (:private-key account))
;=> {:p2pkh "1..." :p2wpkh "bc1..."}
```

## なぜ手書きの BIP-39 wordlist を埋め込まないか

2048 語のリストを記憶から書き起こすと1語でも誤りがあれば実際の recovery
phrase を静かに破壊しうる。同梱の `resources/bip39/english.txt` は
`github.com/bitcoin/bips` の `bip-0039/english.txt` から取得したそのままの
コピーで、`load-wordlist` が読み込み時に SHA-256
(`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) を
検証する。改変・破損・別言語ファイルの取り違えは即座に例外になる。

## Test

```
clojure -M:test
```
