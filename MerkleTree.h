#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

class MerkleTree
{
    protected:
        std::vector<uint64_t*> mempool; // each index of pointer has length of 8
    
    public:
        uint64_t* MerkleRoot()
        {
            IntTypes int_type = IntTypes();
            mempool.push_back(sha512("sender: N/A-receiver: N/A-amount: N/A"));

            __uint128_t len = mempool.size();
            for(int c=0;c<8;c++) {
                // std::cout << std::hex << mempool[0][c] << " ";
// 378882b8368ece7f2fa8f83802cd5c36f7e0390f8512ba24d7e6a7edd9bbd907d15934b5c1fc5
// f29dfc1ba8f8b74eb078f8cb2251a865170d184f7ebe81b3a02
            }
            bool odd = true;
            uint64_t amount_of_leafts = 0;
            __uint128_t tmp_leaf_len = len;
            if(len%2 != odd) {
                while(tmp_leaf_len>1) {
                    tmp_leaf_len -= 2;
                    amount_of_leafts += 1;
                }
            } else {
                while(tmp_leaf_len>0) {
                    if(tmp_leaf_len !=1) {
                    tmp_leaf_len--;tmp_leaf_len--;
                    } else {
                        tmp_leaf_len--;
                    }
                    amount_of_leafts += 1;
                }
            }
            
            // calculate MerkleRoot
            for(__uint128_t c=0;c<len;c++) {
                for(int i=0;i<8;i++) {
                    if (len%2 == odd) {
                        //  = mempool[c][i];
                    } 
                    else if(len%2 != odd) {
                        
                    }
                }
            }
            return nullptr;
        }
};

class Node : public MerkleTree
{
    
};
