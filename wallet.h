/*  Author: Taha Canturk
 *  Github: Kibnakamoto
 *  Repisotory: BlockchainPrototype
 *  Start Date: May 1, 2022
 *  Last Update: May 1, 2022
 */


#ifndef WALLET_H_
#define WALLET_H_

#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <random>
#include <time.h>
#include <tuple>
#include <map>
#include <set>

// 256-bit random number. AES key
std::shared_ptr<uint8_t> generateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[32]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c] = tmp>>24 & 0xff;
        key.get()[c*4+1] = tmp>>16 & 0xff;
        key.get()[c*4+2] = tmp>>8 & 0xff;
        key.get()[c*4+3] = tmp & 0xff;
    }
    return key;
}

// 192-bit random number. AES key
std::shared_ptr<uint8_t> generateAES192Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[24]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c*3+1] = tmp>>16 & 0xff;
        key.get()[c*3+2] = tmp>>8 & 0xff;
        key.get()[c*3+3] = tmp & 0xff;
    }
    return key;
}

// 128-bit random number. AES key
std::shared_ptr<uint8_t> generateAES128Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[16]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c*2] = tmp>>8 & 0xff;
        key.get()[c*2+1] = tmp & 0xff;
    }
    return key;
}

// for user input in UI
template<typename T>
std::string aesKeyToStr(std::shared_ptr<T> key, uint32_t keysize=32)
{
    std::stringstream ss;
    for(int c=0;c<keysize;c++) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (short)key.get()[c];
    }
    return ss.str();
}

// reverse aeskey_tostr function for use in UI, default key size is for aes256
template<typename T>
std::shared_ptr<T> aesKeyToSPtr(std::string strKey, uint32_t keysize=32)
{
    if(strKey.length() != keysize*2) {
        std::cout << "length of key doesn't match required algorithm key size: "
                  << keysize;
        exit(EXIT_FAILURE);
    }
    std::shared_ptr<T> key(new T[keysize]);
    std::string bytes="";
    for(int c=0;c<keysize;c++) {
        bytes += strKey.substr(c*2,2);
        if (c<keysize-1) {
            bytes += " ";
        }
    }
    std::istringstream hexCharsStream(bytes);
    unsigned int ch;
    int i=0;
    while (hexCharsStream >> std::hex >> ch)
    {
        key.get()[i] = ch;
        i++;
    }
    return key;
}

// wallet address has to be 512-bits at all conditions and in hex format
std::shared_ptr<uint64_t> usrInWallet512(std::string walletAddress)
{
    if(walletAddress.length() != 128) {
        std::cout << "input length not 64 bytes";
        exit(EXIT_FAILURE);
    }
    std::shared_ptr<uint64_t> hash(new uint64_t[8]);
    for(int c=0;c<8;c++) {
        std::string substr = "0x" + walletAddress.substr(c*16,16);
        hash.get()[c] = std::stoul(substr, nullptr, 16);
    }
    return hash;
}

struct Transaction {
    // sender and receiver can be reversed and are only variable names
    std::shared_ptr<uint64_t> sender;
    std::shared_ptr<uint64_t> receiver;
    uint32_t amount;
    
    std::string encryptTr(std::shared_ptr<uint8_t> key,std::string buysOrSell)
    {
        AES::AES256 aes256;
        std::string transactionData = "";
        if(buysOrSell == "buy") {
            buysOrSell += "s"; // make it 4 chars
        }

        transactionData += buysOrSell + ", ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
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
        // for length, buy or send isn't required and just use the right amount of chars
        // use buys for buy so that its the same length
        transactionData += "bosc, ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
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
            std::cout << std::endl << std::endl << "AES256 key 1:\t";
            for(int c=0;c<32;c++) {
                std::cout << std::hex << (short)val[0].get()[c] << " ";
            }
            
            std::cout << std::endl << std::endl << "AES256 key 2:\t";
            for(int c=0;c<32;c++) {
                std::cout << std::hex << (short)val[1].get()[c] << " ";
            }
            std::cout << std::endl << std::endl;
        }
        std::cout << "your wallet address:\t";
        std::cout << to8_64_str(sender);
        std::cout << std::endl;
        std::cout << "external wallet address:\t";
        std::cout << to8_64_str(receiver);
        std::cout << std::endl;
        std::cout << "amount:\t" << std::dec << amount;
        std::cout << std::endl << std::endl;
    }
    
    // A single hashed transaction data
    std::shared_ptr<uint64_t> Hash(std::string buysOrSell)
    {
        std::string transactionData = "";
        if(buysOrSell == "buy") {
            buysOrSell += "s"; // make it 4 chars
        }
        transactionData += buysOrSell + ", ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
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
            AESkey = generateAES256Key(); // 32 bytes
            std::shared_ptr<uint8_t> NewAESkey(new uint8_t[32]);
            NewAESkey = generateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey.get()[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump aes256-key") {
                std::cout << std::endl << "AES256 key 1:\t" << aesKeyToStr<uint8_t>(AESkey);
                std::cout << std::endl << std::endl;
                std::cout << "AES256 key 2:\t" << aesKeyToStr<uint8_t>(NewAESkey);
                std::cout << std::endl << std::endl;

            }
            std::vector<std::shared_ptr<uint8_t>> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {sha512(AES256_ciphertext), keys};
        }
        
        // for UI input
        bool verifyInputWallet(std::vector<std::shared_ptr<uint64_t>> walletAddresses,
                               std::shared_ptr<uint64_t> walletAddress)
        {
            // find if walletAddress in vector walletAddresses
            bool walletAValid;
            for(int i=0;i<walletAddresses.size();i++) {
                std::vector<bool> validity;
                for(int c=0;c<8;c++) {
                    if(walletAddresses[i].get()[c] == walletAddress.get()[c]) {
                        validity.push_back(true);
                    } else {
                        validity.push_back(false);
                    }
                }
                
                // find wheter walletAddress is true or false
                if(std::find(validity.begin(), validity.end(), false) !=
                   validity.end()) {
                    walletAValid = false;
                    validity.clear();
                } else {
                    walletAValid = true;
                    break; // stops if true, continues to search if false
                }
            }
            
            // terminate or not
            if(walletAValid) {
                std::cout << "\nwallet address verified";
            } else {
                std::cout << "\nerror: wallet address doesn't exist";
                exit(EXIT_FAILURE);
            }
            return walletAValid;
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
            std::cout << std::hex << to8_64_str(walletAddress);
            std::cout << "\ntrying again";
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
                       shared_ptr<uint8_t>> AESkeysWallet, std::vector<uint32_t>
                       &trnsLengths, std::shared_ptr<uint64_t>
                       walletAddress=nullptr, std::string askForPrivKey="")
        {
            Address address = Address();
            if(walletAddress != nullptr) {
                verifyOwnerData(verifyInfo);
                if(sellorbuy=="send") {
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
                transactionhashes.push_back(trns.Hash(sellorbuy));
                trnsLengths.push_back(trns.length());
                std::shared_ptr<uint8_t> newAES_TrKey(new uint8_t[32]);
                newAES_TrKey = generateAES256Key();
                std::map<std::string, std::shared_ptr<uint8_t>>::iterator
                it = transactionsEnc.begin();
                transactionsEnc.insert(it, std::pair<std::string, std::shared_ptr
                                       <uint8_t>> (trns.encryptTr(newAES_TrKey, sellorbuy),
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
                               storedCrypto, AESkeysWallet, trnsLengths, walletAddress);
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
                    transactionsEnc, int32_t storedCrypto, std::vector<uint32_t>
                    trnsLengths, std::string askForPrivKey="")
    {
        Address address = Address();
        auto [fst,snd] = address.newTransaction(sender, receiver, amount, mempool,
                                                verifyInfo, sellorbuy,
                                                transactionhashes, transactionsEnc,
                                                storedCrypto, AESkeysWallet,
                                                trnsLengths, walletAddress,
                                                askForPrivKey);
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

#endif /* WALLET_H_ */
