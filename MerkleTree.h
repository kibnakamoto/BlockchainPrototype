#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

class MerkleTree
{
    protected:
        std::vector<uint64_t*> mempool; // each index of pointer has length of 8
    
    public:
        std::string MerkleRoot()
        {
            IntTypes int_type = IntTypes();
            mempool.push_back(sha512("sender: N/A-receiver: N/A-amount: N/A"));
            __uint128_t len = mempool.size();
            for(int c=0;c<8;c++) {
                std::cout << std::hex << mempool[0][c] << " ";
// 378882b8368ece7f2fa8f83802cd5c36f7e0390f8512ba24d7e6a7edd9bbd907d15934b5c1fc5
// f29dfc1ba8f8b74eb078f8cb2251a865170d184f7ebe81b3a02
            }
            for(__uint128_t c=len;c>len/2;c--) { // TODO: fix
                
            }
            
            // calculate MerkleTree
            for(__uint128_t c=0;c<len;c++) {
                for(int c=0;c<8;c++) {
                    if (len%2 == 0) {
                        
                    } else {
                        
                    }
                }
            }
            return std::string();
        }
};

class Node : public MerkleTree
{
    
};
