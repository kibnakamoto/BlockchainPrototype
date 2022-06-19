# Blockchain Prototype

Blockchain in c++.

Start Date: Feb 9.

By: Taha Canturk

Email: kibnakanoto@protonmail.com

Licence: GPL-3.0

This is a blockchain prototype I'm creating for a future blockchain I will create. it took me 4 months to code this project, there are around 50 terminal commands that you can use. The blockchain includes terminal input as well as console input. You can even mine but keep in mind that it is a prototype. The consensus mechanism used for validating transactions and mining blocks in this prototype blockchain is the Proof of Work. Since I didn't use boost or another library for multiprecision integers. I had to constantly bitmask and use smart pointers. This also made the search algorithms a lot more complex. For hashing, I use sha512 which I implemented not so long ago. For encryption I wanted to use ECIES (Elliptic Cryptography Integrated Encryption Scheme), ECC (Elliptic Curve Cryptography) algorithm such as brainpoolp512r1 or secp521k1 for public key generation and maybe use ECDSA (Elliptic Cryptographty Digital Signature Algorithm) for digital signatures. Since I didn't jhave access to Crypto++, I had to compromise and use symmetric encryption algorithms that I implemented before, which was all of the AES (Advanced Encryption Standards). I mostly used AES256 for encryption but I did give the user an option to use the other AES algorithms if requested. Altough the algorithms AES128, AES192, AES256 are enough, the project would've been more professional and useful if I had access to boost and Crypto++. Since the project is currently version 1.0, I hope to make some of these changes in the future.

4468 lines of code as of June 19, 2022

Command List:
```
    // descriptions
    /* NOTE: capitalization matters */
        {"help: show basic commands with descriptions",
         " -help: for command description, put after another command",
         "help-all: show all commands with description",
         "show w: show warranty information about the licence",
         "show c: show copying information about the licence",
         "create-wa: generate new wallet address",
         "buy: buy an amount, must specify amount after typing buy",
         "send: send an amount to another wallet",
         "sell: same as send but send to non-existant wallet address",
         "e-wallet-aes128: encrypt wallet with aes256, do not provide wallet address here, provide key",
         "e-wallet-aes192: encrypt wallet with aes192, do not provide wallet address here, provide key",
         "e-wallet-aes256: encrypt wallet with aes256, do not provide wallet address here, provide key",
         "e-wallet-aes128-genkey: encrypt wallet with aes256, do not provide wallet" +
         std::string("address here, do not provide key, for command line, add space after aes128"),
         "e-wallet-aes192-genkey: encrypt wallet with aes192, do not provide wallet" +
         std::string(" address here, do not provide key, for command line, add space after aes192"),
         "e-wallet-aes256-genkey: encrypt wallet with aes256, do not provide wallet" +
         std::string(" address here, do not provide key, for command line, add space after aes256"),
         "decrypt-wallet: decrypt wallet using chosen encryption algorithm, provide key",
         "get p-w keys: request private wallet keys",
         "get p-trns-data: request single transaction data, provide transaction index in wallet",
         "del-wallet: delete your wallet address, make sure wallet is empty before" +
         std::string(" doing so, wallet components will be deleted and cannot be brought back"),
         "exit: will terminate and exit program",
         "quit: will terminate and exit program",
         "burn [amount]: burn an amount of crypto(send to dead wallet address), provide amount",
         "hash-sha512 [input]: hash input with sha512",
         "enc-aes128 -genkey [input,key]: encrypt input with aes128, key is generated for you",
         "enc-aes192 -genkey [input,key]: encrypt input with aes192, key is generated for you",
         "enc-aes256 -genkey [input,key]: encrypt input with aes256, key is generated for you",
         "enc-aes128 [input,key]: encrypt input with aes128, use own key in hex format",
         "enc-aes192 [input,key]: encrypt input with aes192, use own key in hex format",
         "enc-aes256 [input,key]: encrypt input with aes256, use own key in hex format",
         "dec-aes128 [input,key]: decrypt ciphertext with aes128, provide key",
         "dec-aes192 [input,key]: decrypt ciphertext with aes192, provide key",
         "dec-aes256 [input,key]: decrypt ciphertext with aes256, provide key",
         "get myahr: print my average hashrate",
         "get blockchain: prints all blocks in blockchain",
         "get block-hash [block index]: get block hash, provide index",
         "get block-nonce [block index]: get block nonce, provide index",
         "get block-timestamp [block index]: get block timestamp, provide index",
         "get block-merkle-r [block index]: get merkle root of block, provide index",
         "get block-difficulty [block index]: get difficulty of block, provide index",
         "get block-ahr [block index]: get average hash rate of block miners, provide index",
         "get nblocktime: get next block generation time",
         "get blockchain-size: print amounts of blocks in blockchain",
         "get version: get blockchain version",
         "get mempool: print verified mempool hashes in current block",
         "enc-algs: available encryption/decryption algorithms",
         "start mine: start mining",
         "dump-wallet512: dump 512-bit wallet address as hex", // after this is not in version 1
         "get tr-target: print transaction target",
         "get tr-hash: print transaction hash",
         "get tr-ciphertext [trns index]: print transaction ciphertext",
         "get tr-timestamp [trns index]: print transaction timestamp",
         "dump all-trnsData: dump all transaction data in wallet",
         "get blockchain-ahr: get average hashrate over all blockchain",
         "get block-target [block index]: get block target hash, provide index"
         }
```
