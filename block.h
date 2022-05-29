/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: May 29, 2022
*
*/


#ifndef BLOCK_H_
#define BLOCK_H_

#include <iostream>
#include <vector>
#include <ctime>
#include <cmath>
#include <string.h>
#include <stdint.h>
#include <chrono>
#include <unistd.h>
#include <climits>
#include <algorithm>
#include <functional>
#include <sstream>

namespace Blockchain
{
    std::vector<std::string> blockchain;
    std::vector<std::shared_ptr<uint64_t>> Blockhashes;
    
    inline std::string generateTimestamp()
    {
        std::time_t Time = std::time(nullptr);
        return std::asctime(std::localtime(&Time));
    }
    
    template<typename T>
    inline T generateNonce()
    {
        /* random numerical type using Mersenne Twister. Not recommended for 
           cryptography but couldn't find a std cryptographic random nonce generator */
        std::random_device randDev;
        std::mt19937 generator(randDev() ^ time(NULL));
        std::uniform_int_distribution<T> distr;
        return distr(generator);
    }
    
    inline double difficulty(uint64_t nonce) // return 1 in version 1
    {
        return 1;
    }
    
    /* hashes the bitcoin genesis block and adds to vector and length of vector is 
     * hashrate
     */
    inline uint64_t calchashRateSingle()
    {
        std::vector<std::string>hashes;
        auto start = std::chrono::system_clock::now();
        auto end_t = std::chrono::system_clock::now();
        do
        {   // NOTE: bitcoin target 3 times smaller: 10 minute block generation time
            std::string genesisBlockBtc =
            "GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46\
            a2a6c172b3f1b60a8ce26f\nhashMerkleRoot = 0x4a5e1e4baab89f3a3251\
            8a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\ntxNew.vin[0].\
            scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616\
            220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E616843203\
            93030322F6E614A2F33302073656D695420656854\ntxNew.vout[0].nValue\
            = 5000000000\ntxNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A57\
            8D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A\
            60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG\
            block.nVersion = 1\nblock.nTime    = 1231006505\nblock.nBits    \
            = 0x1d00ffff\nblock.nNonce   = 2083236893\nCBlock(hash=000000000\
            019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1\
            e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)\n\
              CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, \
              nLockTime=0)\nCTxIn(COutPoint(000000, -1), coinbase 04ffff0\
              01d0104455468652054696d65732030332f4a616e2f32303039204368616\
              e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c\
              6f757420666f722062616e6b73)\nCTxOut(nValue=50.00000000, script\
              PubKey=0x5F1DF16B2B704C8A578D0B)\nvMerkleTree: 4a5e1e";
            hashes.push_back(sha512_str(genesisBlockBtc));
            end_t = std::chrono::system_clock::now();
        } while (std::chrono::duration_cast<std::chrono::seconds>
                 (end_t - start).count() != 1);
        return hashes.size();
    }
    
    inline uint64_t calcHashRateSha512(uint32_t accuracy=5)
    {
        // TODO: use accuracy as parameter for user to optionally provide in UI
        std::vector<uint64_t> retvector;
        uint64_t ret=0;
        for(int c=0;c<accuracy;c++) {
            retvector.push_back(calchashRateSingle());
            ret += retvector[c];
        }
        ret/=accuracy;
        return ret;
    }
    
    inline double nextBlockTime(double difficulty,
                                uint64_t hashrate=calcHashRateSha512())
    {
        // TODO: avoid output as scientific notation
        double timeM = difficulty * pow(2,32) / hashrate; // microseconds
        return timeM;
    }
};

class PoW
{
    protected:
        std::tuple<bool, std::shared_ptr<uint64_t>, uint64_t>
        mineSingleTr(std::string encryptedTr, std::shared_ptr<uint8_t> key,
                     uint64_t difficulty, std::vector<std::shared_ptr<uint64_t>>
                     mempool, uint64_t nonce, uint64_t trnsLength)
        {
            std::cout << "\ncalculating transaction target...\n";
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            uint64_t newNonce = nonce;
            std::shared_ptr<uint64_t> target(new uint64_t[8]); // transaction target
            
            // assign starting target value
            for(int c=0;c<8;c++) {
                target.get()[c] = sha512(encryptedTr +
                                         std::to_string(newNonce)).get()[c];
            }
            
            /* TODO: decrease target hash for longer generation time once 
             * version 1 is debugged. Or just get rid of target transaction hash
             */
            for(int c=0;c<8;c++) {
                while(target.get()[c] > pow(2,56)) { // define target hash
                    target.get()[c] = sha512(encryptedTr +
                                             std::to_string(newNonce)).get()[c];
                    newNonce++;
                }
            }
            // verify transaction data
            std::cout << "verifying transaction...\n";
            AES::AES256 aes256;
            std::string transactionData = aes256.decrypt(encryptedTr, key);
            std::shared_ptr<uint64_t> hash(new uint64_t[8]);
            bool valid;
            uint64_t index = 0; // index of transaction
            /* Remove padding in beggining caused by decrypting AES256 
             * ciphertext string that isn't a multiple of 16.
             */
            transactionData.erase(trnsLength,transactionData.size()-trnsLength);
            hash = sha512(transactionData);
            for(int i=0;i<mempool.size();i++) {
                std::vector<bool> validity;
                for(int c=0;c<8;c++) {
                    if(mempool[i].get()[c] == hash.get()[c]) { // if any index of mempool matches hash
                        validity.push_back(true);
                    } else {
                        validity.push_back(false);
                    }
                }
                // find wheter transaction is true or false
                if(std::find(validity.begin(), validity.end(), false) !=
                   validity.end()) {
                    valid = false;
                    validity.clear();
                } else {
                    valid = true;
                    break; // stops if true, continues to search if false
                }
                index++;
            }
            // print target hash
            std::cout << "target hash: ";
            for(int c=0;c<8;c++) {
                std::cout << std::hex << target.get()[c];
            }
            std::cout << std::endl;
            std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
            std::cout << "microseconds it took to verify transaction: "
                      << std::dec << std::chrono::duration_cast<std::chrono::
                                     microseconds>(end - begin).count();
            return {valid, hash, index};
        }
    public:
        std::pair<bool, std::vector<std::shared_ptr<uint64_t>>>
        mineBlock(const std::map<std::string, std::shared_ptr<uint8_t>> encryptedTs,
                  uint64_t blockNonce, uint64_t difficulty, std::vector<std::
                  shared_ptr<uint64_t>> mempool, std::shared_ptr<uint64_t>
                  v_merkle_root, std::vector<uint32_t> trnsLengths)
        {
            std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            merkle_root = MerkleTree::merkleRoot(mempool);
            bool merkle_validity;
            for(int c=0;c<8;c++) {
                merkle_validity = (merkle_root.get()[c] == v_merkle_root.get()[c]);
            }
            std::cout << "\nmerkle_root: ";
            for(int c=0;c<8;c++) {
                std::cout << std::hex << merkle_root.get()[c];
            }
            
            if(merkle_validity == false) {
                std::cout << "\nmerkle_root: false";
                std::cout << "\nfalse merkle_root: ";
                for(int c=0;c<8;c++) {
                    std::cout << std::hex << v_merkle_root.get()[c];
                }
                bool v;
                std::shared_ptr<uint64_t> singleTrHash(new uint64_t[8]);
                std::cout << "\nchecking false transaction(s)...\n";
                for (auto const [key, val] : encryptedTs) {
                    uint64_t index = 0;
                    for(int c=0;c<trnsLengths.size();c++) {
                        std::tuple<bool, std::shared_ptr<uint64_t>, uint64_t>
                        minedSingleTr = mineSingleTr(key, val, difficulty, mempool,
                                              blockNonce, trnsLengths[c]);
                        std::tie(v, singleTrHash, index) = minedSingleTr;
                        if(v) {
                            goto stop;
                        }
                    }
                    stop:
                        if(v == false) {
                            std::cout << "\ntransaction hash mismatch, transaction index:\t"
                                      << index << "\n" << "transaction hash: ";
                            for(int c=0;c<8;c++) {
                                std::cout << std::hex << singleTrHash.get()[c];
                            }
                            std::cout << std::endl;
                            mempool.erase(mempool.begin() + index);
                            std::cout << "\ntransaction deleted from mempool";
                        } else {
                            std::cout << "\nvalidated transaction:\t" << index
                                      << " from mempool\ntransaction hash: ";
                            for(int c=0;c<8;c++) {
                                std::cout << std::hex << singleTrHash.get()[c];
                            }
                            std::cout << std::endl;
                        }
                }
            } else {
                std::cout << "\nmerkle_root: true\n\n";
            }
            return {true, mempool}; // cleaned mempool
        }
};

class Block
{
    public:
        std::vector<uint64_t> hashrates;
        
        uint64_t averageHashRate()
        {
            uint64_t avHashrate = 0;
            for(int c=0;c<hashrates.size();c++) {
                avHashrate += hashrates[c];
            }
            avHashrate /= hashrates.size();
            return avHashrate;
        }
        
        // generate block
        std::shared_ptr<uint64_t> genBlock(std::shared_ptr<uint64_t> target,
                                           uint64_t nonce, std::shared_ptr
                                           <uint64_t> merkle_root, double
                                           difficulty)
        {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            bool valid;
            __uint128_t newNonce = (__uint128_t)nonce;
            std::string merkle_root_str = "";
            for(int c=0;c<8;c++) {
                merkle_root_str += std::to_string(merkle_root.get()[c]);
            }
            for(int c=0;c<8;c++) {
                target.get()[c] = sha512(merkle_root_str + std::to_string(newNonce+difficulty)).get()[c];
            }
            
            /* TODO: use difficulty to generate target height instead of 
             * something like const 2 to the power of 54. NOTE: Block generation
             * time with 2^56 = 1-2 minutes.
             */
            for(int c=0;c<8;c++) {
                while(target.get()[c] >= pow(2,48)) {
                    target.get()[c] = sha512(merkle_root_str +
                                             std::to_string(newNonce+difficulty)).get()[c];
                    newNonce++;
                }
            }
            std::cout << "\nBlock target: ";
            for(int c=0;c<8;c++) {
                std::cout << std::hex << target.get()[c] << "";
            }
            std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
            std::cout << "\nmicroseconds it took to generate block: " << std::dec
                      << std::chrono::duration_cast<std::chrono::microseconds>
                         (end - begin).count() << std::endl;
            return target;
        }
        // tuple function that returns block components
        std::tuple</* prevBlockHash */std::shared_ptr<uint64_t>, 
                   /* timestamp */std::string, /* blockchain size */ uint32_t,
                   /* nonce */uint64_t, /* block difficulty */double,
                   /* merkle_root */std::shared_ptr<uint64_t>,
                   /* next block generation time*/double,
                   /* average hashrate */double> data(std::vector<std::shared_ptr
                                                      <uint64_t>> mempool)
       {
            /* use this to represent block in blockchain, use tuple data to 
               compare values in block for testing */
            SHA512 hash = SHA512();
            PoW ProofofWork = PoW();
            std::shared_ptr<uint64_t> target(new uint64_t[8]);
            std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            merkle_root = MerkleTree::merkleRoot(mempool);
            MerkleTree::merkleRoots.push_back(merkle_root);
            std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
            uint32_t blockchainsize = Blockchain::blockchain.size();
            std::string timestamp = Blockchain::generateTimestamp();
            uint64_t nonce = Blockchain::generateNonce<uint64_t>();
            uint64_t randHashNonce = Blockchain::generateNonce<uint64_t>();
            double difficulty = Blockchain::difficulty(randHashNonce);
            uint64_t hashrate = Blockchain::calcHashRateSha512(5); // accuracy=5
            hashrates.push_back(hashrate);
            uint64_t avHashrate = averageHashRate();
            std::cout << "\ngenerating block...\n";
            genBlock(target, nonce, merkle_root, difficulty);
            double blockGenTime = Blockchain::nextBlockTime(difficulty, avHashrate);
            std::cout << "next block will be generated in " << std::dec
                      << blockGenTime << std::endl;
            if(blockchainsize > 1) {
                for(int c=0;c<8;c++) {
                    // subtract 2 from blockchainsize since array starts from zero
                    prevBlockHash.get()[c] = Blockchain::Blockhashes
                                             [blockchainsize-2].get()[c];
                }
            } else {
                for(int c=0;c<8;c++) {
                    prevBlockHash.get()[c] = 0x00ULL;
                }
            }
            
           return {prevBlockHash,timestamp,blockchainsize,nonce,difficulty,
                   merkle_root,blockGenTime,avHashrate};
       }
        
        /* if recreate all block data after mining */
        // std::string data_str(std::vector<std::shared_ptr<uint64_t>> mempool,
        //                      std::string blockchain_version)
        // {
        //     /* use this to represent block in blockchain, use tuple data to 
        //       compare values in block for testing */
        //     std::tuple<std::shared_ptr<uint64_t>,std::string,uint32_t,uint64_t, 
        //               double,std::shared_ptr<uint64_t>, double, double>
        //     block_data = data(mempool);
        //     std::stringstream blockchain_blockdata;
        //     std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
        //     std::string timestamp;
        //     uint32_t blockchainSize;
        //     uint64_t nonce;
        //     double difficulty, nextBlockGenTime, avHashrate;
        //     std::shared_ptr<uint64_t> merkle_root;
        //     std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
        //              merkle_root,nextBlockGenTime, avHashrate) = block_data;
        //     blockchain_blockdata << "previous block hash: ";
        //     for(int c=0;c<8;c++) {
        //         blockchain_blockdata << std::hex
        //                              << prevBlockHash.get()[c];
        //     }
        //     blockchain_blockdata << "\ntimestamp: " << timestamp;
        //     blockchain_blockdata << "blockchain size: "
        //                          << std::dec << blockchainSize;
        //     blockchain_blockdata << "\nnonce: "
        //                          << std::dec << nonce;
        //     blockchain_blockdata << "\ndifficulty: "
        //                          << difficulty;
        //     blockchain_blockdata << "\nmerkle_root: ";
        //     for(int c=0;c<8;c++) {
        //         blockchain_blockdata << std::hex << merkle_root.get()[c];
        //     }
        //     blockchain_blockdata << "\napproximate time until next block: "
        //                          << nextBlockGenTime;
        //     blockchain_blockdata << "\nAverage hashrate of miners: "
        //                          << avHashrate;
        //     blockchain_blockdata << "\nblockchain version: " << blockchain_version;
        //     std::shared_ptr<uint64_t> blockHash;
        //     blockHash = sha512(blockchain_blockdata.str());
        //     blockchain_blockdata << "\nblock hash: ";
        //     for(int c=0;c<8;c++) {
        //         blockchain_blockdata << std::hex << blockHash.get()[c];
        //     }
        //     Blockchain::Blockhashes.push_back(blockHash);
        //     Blockchain::blockchain.push_back(blockchain_blockdata.str());
        //     return blockchain_blockdata.str();
        // }
        /* use UI block data */
        std::string data_str(std::shared_ptr<uint64_t> prevBlockHash, std::string
                             timestamp, uint32_t blockchainSize, uint64_t nonce,
                             double difficulty, double nextBlockGenTime,
                             double avHashrate, std::vector<std::shared_ptr
                             <uint64_t>> clean_mempool, std::string blockchain_version)
        {
            /* use this to represent block in blockchain, use tuple data to
               compare values in block for testing and mining */
            std::stringstream blockchain_blockdata;
            std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            merkle_root = MerkleTree::merkleRoot(clean_mempool);
            blockchain_blockdata << "previous block hash: ";
            for(int c=0;c<8;c++) {
                blockchain_blockdata << std::hex
                                     << prevBlockHash.get()[c];
            }
            blockchain_blockdata << "\ntimestamp: " << timestamp
                                 << "\nblockchain size: "
                                 << std::dec << blockchainSize
                                 << "\nnonce: " << std::dec << nonce
                                 << "\ndifficulty: " << difficulty;
            blockchain_blockdata << "\nmerkle_root: " << to8_64_str(merkle_root);
            blockchain_blockdata << "\napproximate time until next block: "
                                 << nextBlockGenTime;
            blockchain_blockdata << "\nAverage hashrate of miners: "
                                 << avHashrate;
            blockchain_blockdata << "\nblockchain version: " << blockchain_version;
            std::shared_ptr<uint64_t> blockHash;
            blockHash = sha512(blockchain_blockdata.str());
            blockchain_blockdata << "\nblock hash: ";
            for(int c=0;c<8;c++) {
                blockchain_blockdata << std::hex << blockHash.get()[c];
            }
            Blockchain::Blockhashes.push_back(blockHash);
            Blockchain::blockchain.push_back(blockchain_blockdata.str());
            return blockchain_blockdata.str();
        }
};

#endif /* BLOCK_H_ */
