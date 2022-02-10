#include <stdint.h>

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        // This function is made for 256-bit sha256
        inline std::pair<__uint128_t, __uint128_t> __uint256_t(uint32_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>2];
            
            // convert 4 32-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<2;c++) {
                arr128[c] = (((__uint128_t)mempoolSingleHash[c*4]<<96) |
                                          ((__uint128_t)mempoolSingleHash[c*4+1]<<64) |
                                          ((__uint128_t)mempoolSingleHash[c*4+2]<<32) |
                                          (__uint128_t)mempoolSingleHash[c*4+3]);
            }
            return {arr128[0], arr128[1]};
        }
        /* this creates a tuple of 4 variables that are 128-bit each and 
           stores 512-bit unsigned int data */
        inline std::pair<__uint128_t, __uint128_t> __uint512_t(uint64_t mempoolSingleHash[8])
        {
            return {
                (__uint128_t)(((__uint128_t)mempoolSingleHash[0]<<48) | 
                (mempoolSingleHash[1]<<32)) | (__uint128_t)((
                (__uint128_t)mempoolSingleHash[2]<<16) | (mempoolSingleHash[3])), 
                (__uint128_t)(((__uint128_t)mempoolSingleHash[4]<<48) | 
                (mempoolSingleHash[5]<<32)) | (__uint128_t)((
                (__uint128_t)mempoolSingleHash[6]<<16) | (mempoolSingleHash[7]))
                // (__uint128_t)(((__uint128_t)mempoolSingleHash[0]<<64) | 
                // (mempoolSingleHash[1])) | (__uint128_t)((
                // (__uint128_t)mempoolSingleHash[2]<<64) | (mempoolSingleHash[3])), 
                // (__uint128_t)(((__uint128_t)mempoolSingleHash[4]<<64) | 
                // (mempoolSingleHash[5])) | (__uint128_t)((
                // (__uint128_t)mempoolSingleHash[6]<<64) | (mempoolSingleHash[7]))
            };
        }
        // TODO: define 1024 bit int for 2 distinct mempoolSingleHash arrays. 
        // Use this in the sha512 merkle tree.
        
};
