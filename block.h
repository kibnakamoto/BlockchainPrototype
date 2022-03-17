#include <iostream>
#include <vector>
#include <ctime>
#include <string.h>
#include <stdint.h>

namespace Blockchain
{
    std::vector<std::string> blockchain;
    std::vector<uint64_t*> Blockhashes;
    
    inline std::string generateTimestamp()
    {
        std::time_t Time = std::time(nullptr);
        return std::asctime(std::localtime(&Time));
    }
    
    template<class T>
    inline T generateNonce()
    {
        /* random byte using Mersenne Twister. Not recommended for 
           cryptography but couldn't find a cryptographic random byte generator */
        std::random_device randDev;
        std::mt19937 generator(randDev() ^ time(NULL));
        std::uniform_int_distribution<T> distr;
        return distr(generator);
    }
};

class Block
{
    public:
        std::string block(std::vector<uint64_t*> mempool)
        {
            uint64_t* merkle_root = new uint64_t[8];
            MerkleTree::merkleRoot(mempool, merkle_root);
            MerkleTree::merkleRoots.push_back(merkle_root);
            uint64_t* prevBlockHash = new uint64_t[8];
            uint32_t blockchainsize = Blockchain::blockchain.size();
            std::string timestamp = Blockchain::generateTimestamp();
            uint64_t nonce = Blockchain::generateNonce<uint64_t>();
            std::cout << Blockchain::generateTimestamp();
            if(blockchainsize <= 1) {
                prevBlockHash = Blockchain::Blockhashes[blockchainsize-1];
            }
            return std::string();
        }
};
