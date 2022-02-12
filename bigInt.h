#include <stdint.h>
#include <tuple>

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        // This function is made for 256-bit sha256
        inline std::pair<__uint128_t, __uint128_t> __uint256_t(uint32_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>2];
            
            // convert each 4 32-bit unsigned int to 1 128-bit unsigned int
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
        inline std::tuple<__uint128_t, __uint128_t,__uint128_t, __uint128_t>
        __uint512_t(uint64_t mempoolSingleHash[8])
        {
            __uint128_t arr128[8>>1];
            
            // convert each 2 64-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<4;c++) {
                arr128[c] = (((__uint128_t)mempoolSingleHash[c*2]<< 64) |
                             ((__uint128_t)mempoolSingleHash[c*2+1]));
            }
            return {arr128[0], arr128[1], arr128[2], arr128[3]};
        }
        
        // converts 2 array[8] of 64-bit unsigned int into 1 1024 bit tuple
        inline std::tuple<__uint128_t, __uint128_t,__uint128_t, __uint128_t,
                          __uint128_t, __uint128_t,__uint128_t, __uint128_t>
        __uint1024_t(uint64_t mempoolSingleHash1[8], uint64_t mempoolSingleHash2[8])
        {
            // test function
            __uint128_t arr128[8];
            uint64_t hashArr[8<<1];
            for(int c=0;c<8;c++) {
                hashArr[c] = mempoolSingleHash1[c];
                hashArr[c+8] = mempoolSingleHash2[c];
            }
            // convert each 4 32-bit unsigned int to 1 128-bit unsigned int
            for(int c=0;c<8;c++) {
                arr128[c] = (((__uint128_t)hashArr[c*2]<< 64) |
                             ((__uint128_t)hashArr[c*2+1]));
            }
            return {arr128[0], arr128[1], arr128[2], arr128[3], arr128[4], 
                    arr128[5], arr128[6], arr128[7]};
        }
        
        // uint64_t array of 8 to uint8_t array of 64. This is for the Merkle Tree
        inline uint8_t arr64ToCharArr(uint64_t mempoolSingleHash1[8], 
                                   uint64_t mempoolSingleHash2[8])
        {
            uint64_t hashArr[8<<1];
            uint8_t hashchArr[8<<3];
            
            // to avoid data loss
            uint64_t hashcpyArr[8<<3];

            for(int c=0;c<8;c++) {
                hashArr[c] = mempoolSingleHash1[c];
                hashArr[c+8] = mempoolSingleHash2[c];
            }
            
            // convert uint64_t array[8] to byte array[64]
            for(int c=0,k=8<<3,j=0;c<8,k>=0,j<8;c++,k-=8,j++) { // define j in nested loop
                // for(int j=0;j<8;j++)
                // {
                //     hashcpyArr[c*8+j] = hashArr[c]>>k;
                // }
                hashcpyArr[c*8] = hashArr[c]>>56 & 0xff;
                hashcpyArr[c*8+1] = hashArr[c]>>48 & 0xff;
                hashcpyArr[c*8+2] = hashArr[c]>>40 & 0xff;
                hashcpyArr[c*8+3] = hashArr[c]>>32 & 0xff;
                hashcpyArr[c*8+4] = hashArr[c]>>24 & 0xff;
                hashcpyArr[c*8+5] = hashArr[c]>>16 & 0xff;
                hashcpyArr[c*8+6] = hashArr[c]>>8 & 0xff;
                hashcpyArr[c*8+7] = hashArr[c] & 0xff;
            }
            std::cout << "ans:\t" ;
            for(uint64_t c : hashcpyArr)
            {
                std::cout <<  std::hex << c << " ";
            }
            
            return 0;
        }
};