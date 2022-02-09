#include <stdint.h>

class IntTypes
{
    public:
        /* this 256-bit unsigned int turns each transaction of the mempool 
           into 1 numerical variable */
        inline std::pair<__uint128_t, __uint128_t> __uint256_t(uint64_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>1];
            
            // convert 2 64-bit unsigned int to 1 128-bit unsigned int
            // c<8 because mempoolSingleHash is an array of length 8
            for(int c=0;c<4;c++) {
                arr128[c] = (__uint128_t)(((__uint128_t)mempoolSingleHash[c*2]<<
                                           64) | (mempoolSingleHash[c*2+1]));
            }
            /*
                w[i] = (int)((key[4*i]<<24) | (key[4*i+1]<<16) |
                             (key[4*i+2]<<8) | key[4*i+3]);
                i++;
            } while(i < Nk);
            */
            for(__uint128_t c : arr128) {

            }
            // return 2 arr128 var at once
            return {};
        }
};
