/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: N/A
*
* This implementation only works for C++ version 17 or above. 
* C++ 14 also works but gives warning
* 
*/

#include <iostream>
#include <string>
#include <random>
#include <time.h>
#include <tuple>
#include <map>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"
#include "AES.h"
#include "block.h"

// 256-bit random number. AES key
std::shared_ptr<uint8_t> GenerateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[32]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<32-4;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c] = tmp>>24 & 0xff;
        key.get()[c+1] = tmp>>16 & 0xff;
        key.get()[c+2] = tmp>>8 & 0xff;
        key.get()[c+3] = tmp & 0xff;
    }
    return key;
}

// 192-bit random number. AES key
std::shared_ptr<uint8_t> GenerateAES192Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[24]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<24-4;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c+1] = tmp>>16 & 0xff;
        key.get()[c+2] = tmp>>8 & 0xff;
        key.get()[c+3] = tmp & 0xff;
    }
    return key;
}

// 128-bit random number. AES key
std::shared_ptr<uint8_t> GenerateAES128Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[16]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<16-2;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c] = tmp>>8 & 0xff;
        key.get()[c+1] = tmp & 0xff;
    }
    return key;
}


struct Transaction {
    std::shared_ptr<uint64_t> sender;
    std::shared_ptr<uint64_t> receiver;
    uint32_t amount;
    
    std::string encryptTr(std::shared_ptr<uint8_t> key)
    {
        AES::AES256 aes256;
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        
        return aes256.encrypt(transactionData, key);
    }
    
    // to delete padding from decrypted message
    uint64_t length()
    {
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return transactionData.length();
    }
    
    // time since epoch to orginize transactions by timestamp
    __uint128_t getTrTimestamp()
    {
        return std::chrono::duration_cast<std::chrono::duration<
               __uint128_t>>(std::chrono::duration_cast<std::chrono::milliseconds
               >(std::chrono::system_clock::now().time_since_epoch())).count();
    }
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<std::shared_ptr<uint64_t>,std::vector<
                    std::shared_ptr<uint8_t>>> walletData)
    {
        /* walletData = map to verify if owner of the wallet is requesting data dump
         * std::shared_ptr<uint64_t> is WalletAddress and vector of std::shared_ptr
         * <uint8_t> is the string AES key used as plain text and the AES key
         * used as an AES key. walletData vector has length 2 and key used as
         * key is first and string key as std::shared_ptr<uint8_t> is second
         */
        // useless function. Delete if not useful as reference
        std::cout << std::endl << std::endl;
        AES::AES256 aes256;
        std::string AESkeyStr = "";
        std::string AES256_ciphertext = "";
        for (auto const& [key, val] : walletData) {
            for(int c=0;c<32;c++) {
            AESkeyStr += std::to_string(val[1].get()[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
            for(int i=0;i<8;i++) {
                if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                    std::cout << "wallet Data mismatch";
                    exit(EXIT_FAILURE);
                }
            }
            std::cout << std::endl << std::endl << "AES256 key:\t {";
            for(int c=0;c<32;c++) {
                std::cout << "0x" << std::hex << (short)val[1].get()[c];
                if(c<31) {
                    std::cout << ", ";
                }
            }
            std::cout << "}" << std::endl << std::endl;
        }
        std::cout << "sender\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << sender.get()[c];
        }
        std::cout << std::endl;
        std::cout << "receiver\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << receiver.get()[c];
        }
        std::cout << std::endl;
        std::cout << "amount:\t" << std::dec << amount;
        std::cout << std::endl << std::endl;
    }
    
    // A single hashed transaction data
    std::shared_ptr<uint64_t> Hash()
    {
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return sha512(transactionData);
    }
};

class WalletAddress
{
    public:
        std::pair<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        {
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            AES::AES256 aes256;
            std::shared_ptr<uint8_t> AESkey(new uint8_t[32]);
            AESkey = GenerateAES256Key(); // 32 bytes
            std::shared_ptr<uint8_t> NewAESkey(new uint8_t[32]);
            NewAESkey = GenerateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey.get()[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump aes256-key") {
                std::cout << std::endl << "AES256 key:\t";
                for(int c=0;c<32;c++) {
                    std::cout << (short)AESkey.get()[c] << " ";
                }
                std::cout << std::endl << std::endl;
            }
            std::vector<std::shared_ptr<uint8_t>> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {sha512(AES256_ciphertext), keys};
        }
};

class Address
{
    public:
        void verifyOwnerData(const std::map<std::shared_ptr<uint64_t>,
                             std::vector<std::shared_ptr<uint8_t>>> walletData)
        {
            AES::AES256 aes256;
            std::string AESkeyStr = "";
            std::string AES256_ciphertext;
            for (auto const& [key, val] : walletData) {
                for(int c=0;c<32;c++) {
                    AESkeyStr += std::to_string(val[1].get()[c]);
                }
                AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
                for(int i=0;i<8;i++) {
                    if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                        std::cout << "\nwallet data mismatch";
                        exit(EXIT_FAILURE);
                    } else {
                        goto stop;
                    }
                }
            }
            stop:
                std::cout << "\n\nwallet data verified\n\n";
        }
        
        std::pair<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>
        WalletAddressNotFound(std::vector<std::shared_ptr<uint8_t>> AESkeysWallet,
                              std::string askForPrivKey="")
        {
            WalletAddress wallet_address = WalletAddress();
            std::shared_ptr<uint64_t> walletAddress(new uint64_t[8]);
            std::cout << "No wallet address found!\n";
            std::cout << "Generating Wallet Address\n";
            auto [fst, snd] = wallet_address.GenerateNewWalletAddress(askForPrivKey);
            walletAddress = fst;
            AESkeysWallet = snd;
            std::cout << "Wallet Address Generated\nWallet Address:\t";
            for(int c=0;c<8;c++) {
                std::cout << std::hex << walletAddress.get()[c];
            }
            std::cout << "\n\ntrying again";
            return {walletAddress,AESkeysWallet};
            
        }

        // if new transaction added to the Wallet
        std::pair<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>
        newTransaction(std::shared_ptr<uint64_t> sender, std::shared_ptr<uint64_t>
                       receiver, uint32_t amount, std::vector<std::shared_ptr<
                       uint64_t>> &mempool, std::map<std::shared_ptr
                       <uint64_t>, std::vector<std::shared_ptr<uint8_t>>>
                       verifyInfo, std::string sellorbuy, std::vector
                       <std::shared_ptr<uint64_t>>& transactionhashes,
                       std::map<std::string, std::shared_ptr<uint8_t>>&
                       transactionsEnc, int32_t& storedCrypto, std::vector<std::
                       shared_ptr<uint8_t>> AESkeysWallet,std::shared_ptr<uint64_t>
                       walletAddress=nullptr,std::string askForPrivKey="")
        {
            Address address = Address();
            if(walletAddress != nullptr) {
                verifyOwnerData(verifyInfo);
                if(sellorbuy=="sell") {
                    if(amount > storedCrypto) {
                        std::cout << "you do not own " << std::dec << amount
                                  << ". Process failed";
                        sender = walletAddress;
                        exit(EXIT_FAILURE);
                    } else {
                        storedCrypto -= amount;
                        std::cout << "\nyou sold " << std::dec << amount
                                  << "\nyou now own "
                                  << storedCrypto;
                    }
                } else if(sellorbuy=="buy") {
                    
                    storedCrypto += amount;
                    std::cout << "\n"  << std::dec << amount
                              << " bought.\nyou now own " << storedCrypto
                              << "\n\n";
                    receiver = walletAddress;
                }
                
                struct Transaction trns{sender, receiver, amount};
                transactionhashes.push_back(trns.Hash());
                std::shared_ptr<uint8_t> newAES_TrKey(new uint8_t[32]);
                newAES_TrKey = GenerateAES256Key();
                std::map<std::string, std::shared_ptr<uint8_t>>::iterator
                it = transactionsEnc.begin();
                transactionsEnc.insert(it, std::pair<std::string, std::shared_ptr
                                       <uint8_t>> (trns.encryptTr(newAES_TrKey),
                                                   newAES_TrKey));
                mempool.push_back(transactionhashes[transactionhashes.size()-1]);
            } else {
                std::cout << "\nERR:\tWalletAddressNotFound\n";
                auto [fst, snd] = WalletAddressNotFound(AESkeysWallet,
                                                        askForPrivKey);
                walletAddress = fst;
                AESkeysWallet = snd;
                std::cout << "\nNew Wallet Address Created";
                newTransaction(sender, receiver, amount, mempool, verifyInfo,
                               sellorbuy, transactionhashes, transactionsEnc,
                               storedCrypto, AESkeysWallet, walletAddress);
                std::cout << "\nTransaction complete" << std::endl << std::endl;
            }
            return {walletAddress,AESkeysWallet};
        }
};

struct Wallet {
    /* parameters to verify when owner of the wallet is modifying */
    // should be nullptr if WalletAddressNotFound
    std::shared_ptr<uint64_t> walletAddress;
    
    // can be empty if WalletAddressNotFound
    std::vector<std::shared_ptr<uint8_t>> &AESkeysWallet;  // length of 2
    
    /* verifyInfo includes AESkeysWallet in the first and second index. 
      If they don't match, don't change anything on the Wallet */
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> verifyInfo;
    
    std::pair<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>
    new_transaction(std::shared_ptr<uint64_t> sender, std::shared_ptr<uint64_t>
                    receiver, uint32_t amount, std::vector<std::shared_ptr<
                    uint64_t>> mempool, std::string sellorbuy, std::vector<
                    std::shared_ptr<uint64_t>> transactionhashes,
                    std::map<std::string, std::shared_ptr<uint8_t>>&
                    transactionsEnc, int32_t storedCrypto, std::string
                    askForPrivKey="")
    {
        Address address = Address();
        auto [fst,snd] = address.newTransaction(sender, receiver, amount, mempool,
                                                verifyInfo, sellorbuy,
                                                transactionhashes, transactionsEnc,
                                                storedCrypto, AESkeysWallet,
                                                walletAddress, askForPrivKey);
        return {fst,snd};
    }
    void verifyOwnerData()
    {
        Address address = Address();
        address.verifyOwnerData(verifyInfo);
    }
    
    std::shared_ptr<uint64_t> WalletAddressNotFound(std::string askForPrivKey="")
    {
        Address address = Address();
        auto [fst,snd] = address.WalletAddressNotFound(AESkeysWallet, askForPrivKey);
        AESkeysWallet = snd;
        return fst;
        
    }
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    WalletAddress wallet_address = WalletAddress();
    SHA512 hash = SHA512();
    Block block = Block();
    PoW ProofofWork = PoW();
    AES::AES128 aes128;
    AES::AES192 aes192;
    AES::AES256 aes256;
    std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]); // declare Merkle Root
    std::shared_ptr<uint64_t> walletAddress(new uint64_t[8]);
    std::vector<std::shared_ptr<uint64_t>> mempool; // declare mempool
    std::vector<std::shared_ptr<uint64_t>> walletAddresses; // All wallet addresses
    std::string blockchain_version = "1.0";
    bool blockMined = false;
    /* TODO: add UI for wallet address creation, buy, sell, verify, login, 
     * sign-in, dump wallet data, allow manual encryption for wallet 
     * address and automatic encryption for wallet data, only allow login and
     * data decryption if database found user info match. No need for GUI yet.
     */
    
    /* TEST PoW MINE */
    // struct Transaction trns{sha512("sender"), sha512("receiver"), 50000};
    // struct Transaction trns1{sha512("sener"), sha512("receiver"), 54000};
    // struct Transaction trns2{sha512("sender"), sha512("reciver"), 35600};
    // struct Transaction trns3{sha512("nder"), sha512("receiver"), 50000};
    // struct Transaction trns4{sha512("sender"), sha512("receiver"), 40000};
    // mempool.push_back(trns.Hash());
    // mempool.push_back(trns1.Hash());
    // mempool.push_back(trns2.Hash());
    // mempool.push_back(trns3.Hash());
    // mempool.push_back(trns4.Hash()); // 5 transactions
    // mempool.push_back(trns.Hash());
    // mempool.push_back(trns1.Hash());
    // mempool.push_back(trns2.Hash()); // 8 transactions
    // std::shared_ptr<uint8_t> AES_key_mining(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining1(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining2(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining3(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining4(new uint8_t[32]);
    // AES_key_mining = GenerateAES256Key();
    // AES_key_mining1 = GenerateAES256Key();
    // AES_key_mining2 = GenerateAES256Key();
    // AES_key_mining3 = GenerateAES256Key();
    // AES_key_mining4 = GenerateAES256Key();
    // std::map<std::string, std::shared_ptr<uint8_t>> transactionsEnc;
    // std::map<std::string, std::shared_ptr<uint8_t>>::iterator it = transactionsEnc.begin();
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns3.encryptTr(AES_key_mining3), AES_key_mining3)); // 3
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns4.encryptTr(AES_key_mining4), AES_key_mining4)); // 4
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    // std::vector<std::shared_ptr<uint64_t>> mempool2;
    // mempool2.push_back(trns.Hash());
    // mempool2.push_back(trns1.Hash());
    // mempool2.push_back(trns2.Hash());
    // mempool2.push_back(trns3.Hash());
    // mempool2.push_back(trns4.Hash()); // 5 transactions
    // mempool2.push_back(trns.Hash());
    // mempool2.push_back(trns1.Hash());
    // mempool2.push_back(trns2.Hash()); // 8 transactions
    // mempool2.push_back(trns1.Hash()); // false from here
    // mempool2.push_back(trns2.Hash());
    
    /* UI */
    std::string newUserIn;
    std::vector<std::string> listOfCommands {"help", "-help", "help-all", "create-wa",
                                             "buy","sell", "e-wallet-aes256",
                                             "e-wallet-aes128","e-wallet-aes192",
                                             "e-wallet-aes256-genkey",
                                             "e-wallet-aes192-genkey",
                                             "e-wallet-aes128-genkey",
                                             "d-wallet-aes256","d-wallet-aes128",
                                             "d-wallet-aes192",
                                             "get p-w key", "get p-trns key",
                                             "send", "del-wallet","exit","quit"
                                             "burn", "hash-sha512","enc-aes128-genkey",
                                             "enc-aes192-genkey","enc-aes256-genkey",
                                             "enc-aes128", "enc-aes192",
                                             "enc-aes256","dec-aes128", "dec-aes192",
                                             "dec-aes256","get blockchain",
                                             "get myahr", "get block-hash", 
                                             "get block-nonce",
                                             "get block-timestamp",
                                             "get block-merkle root",
                                             "get block-difficulty", "get block-ahr",
                                             "get nblocktime", "get blockchain-size",
                                             "get version", "get mempool",
                                             "get tr-target", "get tr-hash",
                                             "get tr-ciphertext", "get tr-timestamp",
                                             "dump all-trnsData", "dump trnsData",
                                             "get blockchain-ahr", "get block-target",
                                             "enc-algs", "start mine", "end mine"};
    std::vector<std::string> commandDescriptions
    // include log in to wallet address command
    {"help: show basic commands with descriptions",
     "-help: for command description, put after another command",
     "help-all: show all commands with description",
     "create-wa: generate new wallet address",
     "buy: buy an amount, must specify amount after typing buy",
     "sell: sell an amount, must specify amount after typing sell",
     "e-wallet-aes128: encrypt wallet with aes256, do not provide wallet address here, provide key",
     "e-wallet-aes192: encrypt wallet with aes192, do not provide wallet address here, provide key",
     "e-wallet-aes256: encrypt wallet with aes256, do not provide wallet address here, provide key",
     "e-wallet-aes128-genkey: encrypt wallet with aes256, do not provide wallet" +
     std::string("address here, do not provide key"),
     "e-wallet-aes192-genkey: encrypt wallet with aes192, do not provide wallet" +
     std::string(" address here, do not provide key"),
     "e-wallet-aes256-genkey: encrypt wallet with aes256, do not provide wallet" +
     std::string(" address here, do not provide key"),
     "d-wallet-aes128: decrypt wallet using aes128, provide key",
     "d-wallet-aes192: decrypt wallet using aes192, provide key",
     "d-wallet-aes256: decrypt wallet using aes256, provide key",
     "get p-w key: request private wallet key", "get p-trns key request single" +
     std::string(" transaction key, provide transaction index in wallet"),
     "send: send to another wallet address, provide wallet address and amount",
     "del-wallet: delete your wallet address, make sure wallet is empty before" +
     std::string(" doing so, wallet components will be deleted and cannot be brought back"),
     "exit: will terminate and exit program",
     "quit: will terminate and exit program",
     "burn [amount]: burn an amount of crypto(send to dead wallet address), provide amount",
     "hash-sha512 [input]: hash input with sha512",
     "enc-aes128-genkey [input,key]: encrypt input with aes128, key is generated for you",
     "enc-aes192-genkey [input,key]: encrypt input with aes192, key is generated for you",
     "enc-aes256-genkey [input,key]: encrypt input with aes256, key is generated for you",
     "enc-aes128 [input,key]: encrypt input with aes128, use own key in decimal format",
     "enc-aes192 [input,key]: encrypt input with aes192, use own key in decimal format",
     "enc-aes256 [input,key]: encrypt input with aes256, use own key in decimal format",
     "dec-aes128 [input,key]: decrypt ciphertext with aes128, provide key",
     "dec-aes192 [input,key]: decrypt ciphertext with aes192, provide key",
     "dec-aes256 [input,key]: decrypt ciphertext with aes256, provide key",
     "get myahr: print my average hashrate",
     "get blockchain: prints all blocks in blockchain",
     "get block-hash [block index]: get block hash, provide index",
     "get block-nonce [block index]: get block nonce, provide index",
     "get block-timestamp [block index]: get block timestamp, provide index",
     "get block-merkle root [block index]: get merkle root of block, provide index",
     "get block-difficulty [block index]: get difficulty of block, provide index",
     "get block-ahr [block index]: get average hash rate of block miners, provide index",
     "get nblocktime: get next block generation time",
     "get blockchain-size: print amounts of blocks in blockchain",
     "get version: get blockchain version",
     "get mempool: print verified mempool hashes in current block",
     "enc-algs: available encryption/decryption algorithms",
     "start mine: start mining", "end mine: end mining", // after this is not in version 1
     "get tr-target: print transaction target",
     "get tr-hash: print transaction hash",
     "get tr-ciphertext [trns index]: print transaction ciphertext",
     "get tr-timestamp [trns index]: print transaction timestamp",
     "dump all-trnsData: dump all transaction data in wallet",
     "dump trnsData [trns index]: dump single transaction data, provide transaction index",
     "get blockchain-ahr: get average hashrate over all blockchain",
     "get block-target [block index]: get block target hash, provide index"};
    std::string userInput = "create-wa";
    // std::cout << "for basic command list, input \"help\"\n"
    //           << "for all commands, input \"help-all\"\n";
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
    itWalletMap = walletMap.begin();
    std::vector<std::shared_ptr<uint8_t>> senderAESkey;
    std::vector<std::shared_ptr<uint8_t>> receiverAESkey;
    std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
    
    // transaction list in wallet
    std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
    
    std::shared_ptr<uint64_t> senderWallet(new uint64_t[8]);
    
    if(userInput == "help") {
        for(int c=0;c<18;c++)
            std::cout << commandDescriptions[c] << "\n";
    }
    else if(userInput == "help-all") {
        if(blockchain_version != "1.0") {
            for(int c=0;c<commandDescriptions.size();c++)
                std::cout << commandDescriptions[c] << "\n";
        } else {
            for(int c=0;c<commandDescriptions.size()-9;c++)
                std::cout << commandDescriptions[c] << "\n";
        }
    }
    else if(userInput.length()>5 && userInput.substr(userInput.length()-5,
                                                     userInput.length()) == "-help") {
        for(int c=0;c<commandDescriptions.size()-1;c++) {
            if(commandDescriptions[c].starts_with(userInput.substr(0,userInput.length()-5))) {
                std::cout << "\n" << commandDescriptions[c];
                break;
            } else {
                std::cout << "\n" << "error: command not found";
            }
        }
    }
    else if(userInput == "create-wa") {
        std::cout << "\ncreating wallet address...\n";
        auto [fstNewAddrs,sndNewAddrs] = wallet_address.GenerateNewWalletAddress("dump aes256-key");
        std::cout << "wallet address created\nwallet address:\t";
        walletAddress = fstNewAddrs;
        for(int c=0;c<8;c++) {
            std::cout << std::hex << walletAddress.get()[c];
        }
        std::cout << std::endl;
        walletAddresses.push_back(walletAddress);
        walletMap.insert(itWalletMap, std::pair<std::shared_ptr<uint64_t>,
                         std::vector<std::shared_ptr<uint8_t>>>(walletAddress,
                                                                sndNewAddrs));
    }
    else if(userInput == "buy" || userInput == "sell") {
        // ask for walletAddress of receiver or seller, key isn't requiried
        if(userInput == "buy") {
            // call function
        } else { // sell
            // call function
        }
    }
    
    // DEBUG
    // std::cout << commandDescriptions.size() << "\n\n" << listOfCommands.size();
    
    std::cout << "\n\nline 339, main.cpp:\t";
    /* TEST walletAddress */
    // std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> testMap;
    // std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
    // itMap = testMap.begin();
    // std::vector<std::shared_ptr<uint8_t>> senderAESmap;
    // std::vector<std::shared_ptr<uint8_t>> receiverAESmap;
    // std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
    
    // transaction list in wallet
    // std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
    
    // std::shared_ptr<uint64_t> senderWallet(new uint64_t[8]);
    // auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    // auto [fst1,snd1] = wallet_address.GenerateNewWalletAddress();
    // walletAddress = fst; // receiver
    // receiverAESmap = snd;
    // senderWallet = fst1;
    // senderAESmap = snd1;
    // walletAddresses.push_back(walletAddress);
    // walletAddresses.push_back(senderWallet);
    
    // encrypted transaction data for a single wallet.
    // std::map<std::string, std::shared_ptr<uint8_t>> transactionsEnc;
    // std::map<std::string, std::shared_ptr<uint8_t>>::iterator it = transactionsEnc.begin();
    
    /* only insert own wallet data to testMap, burning will be sending crypto 
     * to dead account. you have to make sure to have the correct wallet address
     * to send to
     */
    // testMap.insert(itMap, std::pair<std::shared_ptr<uint64_t>, 
    //               std::vector<std::shared_ptr<uint8_t>>>(walletAddress, receiverAESmap));
    // struct Wallet TestWallet{nullptr, snd, testMap};
    // auto [Fst,Snd] = TestWallet.new_transaction(senderWallet,walletAddress,/*amount*/ 50000,
    //                                             mempool,"buy", transactionhashesW,
    //                                             transactionsEnc, 
    //                                             /* storedCrypto */ 20000,
    //                                             "dump aes256-key");
    // walletAddress = Fst;
    // receiverAESmap = Snd;
    /* TEST walletAddress DONE */
    
    // if(blockMined == false) {
    //     std::vector<uint64_t> trnsLength;
    //     /* TEST PoW MINE */
    //     trnsLength.push_back(trns.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     trnsLength.push_back(trns3.length());
    //     trnsLength.push_back(trns4.length());
    //     trnsLength.push_back(trns.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     /* TEST PoW MINE */
    //     std::tuple<std::shared_ptr<uint64_t>,std::string,uint32_t,uint64_t, 
    //           double,std::shared_ptr<uint64_t>, double, double>
    //     unverified_block_data = block.data(mempool2);
    //     uint32_t blockchainSize;
    //     uint64_t nonce;
    //     std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
    //     std::string timestamp;
    //     double difficulty, nextBlockGenTime, avHashrate;
    //     std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
    //              merkle_root,nextBlockGenTime, avHashrate) = unverified_block_data;
    //     auto [isblockmined,clean_mempool] = ProofofWork.mineBlock(transactionsEnc,
    //                                                               nonce, difficulty,
    //                                                               mempool,
    //                                                               merkle_root,
    //                                                               trnsLength);
    //     std::cout << "\nmempool cleaned";
    //     blockMined = isblockmined;
        
    //     if(blockMined) {
    //         std::cout << "\nblock mined successfully";
    //         std::cout << "\nrepresenting correct block in blockhain...\n\n";
    //         std::cout << block.data_str(prevBlockHash,timestamp,blockchainSize,
    //                                     nonce,difficulty,nextBlockGenTime,
    //                                     avHashrate,clean_mempool,blockchain_version);
    //         std::cout << "\n\nblock added to blockchain";
    //         /* wrong mempool cannot have less than correct mempool since wrong
    //          * mempool has new false transaction, if there is a modified 
    //          * transaction hash, it won't work, therefore needs further updates.
    //          * More functionality will be added in further versions
    //          */
    //          std::cout << "\n\nclean mempool: \n";
    //          for(int i=0;i<clean_mempool.size();i++) {
    //              for(int c=0;c<8;c++)
    //                 std::cout << std::hex << clean_mempool[i].get()[c];
    //             std::cout << std::endl;
    //          }
    //     }
    // }
    std::cout << "\nline 339, main.cpp complete";
    return 0;
}
