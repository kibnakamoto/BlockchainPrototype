# Blockchain Prototype

Blockchain in c++.

Date: Feb 9.

By: Taha Canturk

Email: kibnakanoto@protonmail.com

This is a blockchain prototype I'm creating for a future blockchain I will create.

2965 lines of code as of apr 27, 2022

Command List:
```
    // descriptions
    /* NOTE: capitalization matters */
    /* help: show basic commands with descriptions
     * -help: for command description, put after another command
     * help-all: show all commands with description
     * create-wa: generate new wallet address
     * buy: buy an amount, must specify amount after typing buy
     * sell: sell an amount, must specify amount after typing sell
     * e-wallet-[encryption algorithm]: encrypt wallet, do not give wallet 
       address here but provide encryption algorithm and key
       * e-wallet[encryption algorithm]-genkey: encrypt wallet, do not give wallet 
       address here but provide encryption algorithm, key is generated 
     * d-wallet-[decryption algorithm]: decrypt wallet, provide key
     * get p-w key: request private wallet key
     * get p-trns key request single transaction key, provide transaction index
       in wallet
     * send: send to another wallet address, provide wallet address and amount
     * del-wallet: delete your wallet address, make sure wallet is empty before
       doing so, wallet components will be deleted and cannot be brought back
     * [exit]or[quit]: will terminate and exit program
     * burn [amount]: burn an amount of crypto(send to dead wallet address). provide amount
     * hash-sha512 [input]: hash input with sha512
     * enc-aes128-genkey [input,key]: encrypt input with aes128, key is generated for you
     * enc-aes192-genkey [input,key]: encrypt input with aes192, key is generated for you
     * enc-aes256-genkey [input,key]: encrypt input with aes256, key is generated for you
     * enc-aes128 [input,key]: encrypt input with aes128, use own key in decimal format.
     * enc-aes192 [input,key]: encrypt input with aes192, use own key in decimal format.
     * enc-aes256 [input,key]: encrypt input with aes256, use own key in decimal format.
     * dec-aes128 [input,key]: decrypt ciphertext with aes128, provide key
     * dec-aes192 [input,key]: decrypt ciphertext with aes192, provide key
     * dec-aes256 [input,key]: decrypt ciphertext with aes256, provide key
     * get myahr: get my average hashrate
     * get blockchain: prints all blocks in blockchain
     * get block-hash [block index]: get block hash, provide index
     * get block-nonce [block index]: get block nonce, provide index
     * get block-timestamp [block index]: get block timestamp, provide index
     * get block-merkle root [block index]: get merkle root of block, provide index
     * get block-difficulty [block index]: get difficulty of block, provide index
     * get block-ahr [block index]: get average hash rate of block miners, provide index
     * get nblocktime: get next block generation time
     * get blockchain-size: print amounts of blocks in blockchain
     * get version: get blockchain version
     * get mempool: print verified mempool hashes in current block
     * NOT IN VERSION 1:
        * get tr-target: print transaction target
        * get tr-hash: print transaction hash
        * get tr-ciphertext [trns index]: print transaction ciphertext
        * get tr-timestamp [trns index]: print transaction timestamp
        * dump all-trnsData: dump all transaction data in wallet
        * dump trnsData [trns index: dump single transaction data, provide
          transaction index
        * get blockchain-ahr: get average hashrate over all blockchain
        * get block-target [block index]: get block target hash, provide index
     */
```
