#include <stdint.h>
#include <vector>
#include <string>
#include <memory>
#include "sha512.h"

namespace MerkleTree
{
        std::vector<std::shared_ptr<uint64_t>> merkleRoots;
        
        inline uint64_t length(std::vector<std::shared_ptr<uint64_t>> mempool)
        {
            return mempool.size();
        }
        
        class Node
        {
            private:
                std::vector<std::shared_ptr<uint64_t>> append_level(std::vector
                                                                    <std::shared_ptr
                                                                    <uint64_t>>
                                                                    Plevel,
                                                                    uint64_t len)
                {
                    SHA512 hash = SHA512();
                    std::vector<std::shared_ptr<uint64_t>> nodes;
                    for(double c=0;c<len/2;c++) {
                            nodes.push_back(hash.sha512_ptr(Plevel[(uint64_t)(c*2)],
                                                            Plevel[(uint64_t)(c*2+1)]));
                    }
                    
////////////////// Layer 1
// a3d36d02d43fb871ec5d8cc215238bf6a524b113b9c1e3e442f64a4a7ffe4e775041bfc4ece909ad48331da88e2faff5c244bbdfbe09263f4138bf1a39da6afd
// b6a64328f5c7855802f9a0675f8c39481856eb16a90144f8f61be6988bd3fa2d7d51761e96786449fe535c9796c4f9e48ebb8d1d5e62b7f4e3d073ecb6b110bc
// 1e85143d6d6512bc6b37327df3ad595aa8e07c83e9b5a5271a793a4ec5e4694d15008c840c1641091f983c2d41957ddbe36c317180cd8ab6f424e264165a86dd
// 4c0eca97e6c46a4141cd624570e83070b55d0cd139cda6bce406fa0ce594bfe6864d4942e99675290ce7825adf6c18723a227263e02e07b2578f853188f544ec
////////////////// Layer 2
// 57920167e6b0c5d2d6fc80590f161988eb89516a21aec25b2633aac24003a62e3ad665e94bbbb7e7b885baeadecca8abad77ce810d4dab9ab2a029ac77953c59
// 33c709af44fd3e363ee91118d9d95e255fecb86981db515755e07476f33dfdcbfac36d7e4a245801b441a636123f79d31e387d40fff4b7a4b1a65e8e8f4b3a97
////////////////// MERKLE ROOT
// c03892c2b9b71691959172ae83a5c601a53d815c2fe2b0afdfcc6024e4038c740d031b3b2e02dd49d64ad8e4c5fcffd7135d6c2b0c1b8e690c379287da75e03d
                    for(int c=0;c<len/2;c++) {
                        for(int i=0;i<8;i++) {
                            std::cout << std::hex << nodes[c].get()[i] << "";
                            if(i==7) {
                                std::cout << std::endl << std::endl;
                                std::cout << c << "\n\n";
                            }
                        }
                    }
                    /* nodes are single a layer of the MerkleTree */
                    return nodes;
                }
            public:
                void append_levels(std::vector<std::shared_ptr<uint64_t>> mempool, 
                                   uint64_t len, std::shared_ptr<uint64_t>
                                   merkle_root)
                {
                    uint64_t currlen = len;
                    std::vector<std::shared_ptr<uint64_t>> level = mempool;
                    while(currlen != 1) {
                        level = append_level(level, currlen);
                        currlen/=2;
                    } if(level.size() == 1) {
                        merkle_root = std::move(std::shared_ptr<uint64_t>
                                                (level[0]));
                        std::cout << "merkleRoot: "; 
                        // c03892c2b9b71691959172ae83a5c601a53d815c2fe2b0afdfcc
                        // 6024e4038c740d031b3b2e02dd49d64ad8e4c5fcffd7135d6c2b
                        // 0c1b8e690c379287da75e03d
                        for(int c=0;c<8;c++) {
                            std::cout << std::hex << merkle_root.get()[c] << " ";
                        }
                        
                        std::cout << "\nMERKLE_ROOT condition met\n";
                    } else {
                        std::cout << "ERROR, MERKLE_ROOT condition not met";
                        exit(EXIT_FAILURE);
                    }
                }
        };
        
        inline void merkleRoot(std::vector<std::shared_ptr<uint64_t>> Mempool,
                               std::shared_ptr<uint64_t> merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            Node node = Node();
            
            // to avoid 0 hashes to be invalid transactions in Mempool
            std::vector<std::shared_ptr<uint64_t>> mempool = Mempool;
            
            uint64_t len = mempool.size(); // amount of transactions in the block
            uint64_t validlen = 2;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                std::shared_ptr<uint64_t> oddZfill(new uint64_t[8]);
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++; // update len
            }
            
            // calculate amount of layers
            while(validlen != 0) {
                validlen/=2;
                /* validlen gets set to zero so don't use it after this loop */
            }
            // calculate MerkleRoot
            node.append_levels(mempool, len, merkle_root);
            
            // store merkle_root in vector merkleRoots
            merkleRoots.push_back(merkle_root);
        }
}; // namespace MerkleTree
