#include <stdint.h>
#include <tuple>
#include <string.h> // for memcpy
#include <memory>

class IntTypes
{
    // make these a tuple so that concatinating more than 2 values is possible
    public:
        // This function is made for 256-bit sha256
        inline std::pair<__uint128_t, __uint128_t> __uint256_pair(uint32_t mempoolSingleHash[8])
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
        __uint512_tuple(uint64_t mempoolSingleHash[8])
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
        __uint1024_tuple(uint64_t mempoolSingleHash1[8], uint64_t mempoolSingleHash2[8])
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
        inline std::shared_ptr<uint8_t> arr64ToCharArr(std::shared_ptr<uint64_t>
                                                       mempoolSingleHash1,
                                                       std::shared_ptr<uint64_t>
                                                       mempoolSingleHash2)
        {
            std::shared_ptr<uint64_t> hashArr(new uint64_t[16]);
            std::shared_ptr<uint8_t> hashchArr(new uint8_t[128]);
            
            for(int c=0;c<8;c++) {
                hashArr.get()[c] = mempoolSingleHash1.get()[c];
                hashArr.get()[c+8] = mempoolSingleHash2.get()[c];
            }
            
            // convert uint64_t array[16] to byte array[128]
            // for(int c=0;c<16;c++) {
            //     hashchArr.get()[c*8] = hashArr.get()[c]>>56 & 0xff;
            //     hashchArr.get()[c*8+1] = hashArr.get()[c]>>48 & 0xff;
            //     hashchArr.get()[c*8+2] = hashArr.get()[c]>>40 & 0xff;
            //     hashchArr.get()[c*8+3] = hashArr.get()[c]>>32 & 0xff;
            //     hashchArr.get()[c*8+4] = hashArr.get()[c]>>24 & 0xff;
            //     hashchArr.get()[c*8+5] = hashArr.get()[c]>>16 & 0xff;
            //     hashchArr.get()[c*8+6] = hashArr.get()[c]>>8 & 0xff;
            //     hashchArr.get()[c*8+7] = hashArr.get()[c] & 0xff;
            // }
            
            for(int c=0;c<16;c++) {
                for(int i=56,k=0;i>=0,k<8;i-=8,k++) {
                    hashchArr.get()[c*8+k] = hashArr.get()[c]>>i & 0xff;
                }
            }

            return hashchArr;
        }
};





/* Author: Taha Canturk
*  Github: Kibnakamoto
*   Repisotory: AES
*  Start Date: March, 5, 2022
*  Finalized: March 11, 2022
*/


#include <iostream>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <iomanip>

class AES
{
    // operations of aes 256, 128, 192
    class OPS_AES
    {
        /* ENCRYPTION/DECRYPTION */
        private:
            // Rijndael's S-box as a 2-dimentional matrix
            const uint8_t sbox[16][16] = {
                {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 
                0x2B, 0xFE, 0xD7, 0xAB, 0x76}, {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
                0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, {0xB7,
                0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
                0x71, 0xD8, 0x31, 0x15}, {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
                0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, {0x09, 0x83,
                0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
                0xE3, 0x2F, 0x84}, {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
                0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, {0xD0, 0xEF, 0xAA,
                0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
                0x9F, 0xA8}, {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
                0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, {0xCD, 0x0C, 0x13, 0xEC,
                0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
                0x73}, {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
                0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, {0xE0, 0x32, 0x3A, 0x0A, 0x49,
                0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
                0xEA, 0x65, 0x7A, 0xAE, 0x08}, {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
                0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, {0x70,
                0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
                0x86, 0xC1, 0x1D, 0x9E}, {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
                0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, {0x8C, 0xA1,
                0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 
                0x54, 0xBB, 0x16}};
            
            // Rijndael's inverse S-box as a 2-dimentional matrix
            const uint8_t inv_sbox[16][16] = {
                {0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54,
                0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb,
                0x42, 0xfa, 0xc3, 0x4e}, {0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8,
                0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab,
                0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45,
                0x6}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 
                0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f,
                0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37,
                0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
                0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc,
                0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
                0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7,
                0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51,
                0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 
                0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
                0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x4,
                0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
                0xc, 0x7d}};
        public:
            // round constant array
            const uint8_t rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                                      0x40, 0x80, 0x1b, 0x36};

            
            // Galois Field Multipication 2^8
            uint8_t GF256(uint8_t x, uint8_t y)
            {
                /* implemented with bitmasking for efficient and safe 
                   cryptographical use. */
                uint8_t p=0;
                for(int c=0;c<8;c++) {
                    p ^= (uint8_t)(-(y&1)&x);
                    x = (uint8_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
                    y >>= 1;
                }
                return p;
            }
            
            // bitwise circular-left-shift operator for rotating by 8 bits.
            uint32_t rotword(uint32_t x)
            {
                return (x<<8)|(x>>32-8);
            }
            
            /* ENCRYPTION */
            uint8_t** subBytes(uint8_t** b, uint8_t Nb)
            {
                /* seperates hex byte into 2 4 bits and use them as index to
                   sub in values as index of s-box */
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = b[r][c] & 0x0fU;
                        uint8_t high_mask = b[r][c] >> 4;
                        b[r][c] = sbox[high_mask][low_mask];
                    }
                }
                return b;
            }
            
            // shifting rows
            uint8_t** shiftrows(uint8_t** state, uint8_t Nb)
            {
               // to stop values from overriding, use 2 arrays with the same values
               uint8_t pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       pre_state[r][c] = state[r][c];
               }
                // ShiftRows operation. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = pre_state[r][(r+c)%4];
                }
                return state;
            }
            
            uint8_t** mixcolumns(uint8_t** state, uint8_t Nb)
            {
                // lambda function xtime
                auto xtime = [] (uint8_t x)
                {
                    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
                };
                
                for(int c=0;c<Nb;c++) {
                    // create temporary array to stop overriding
                    uint8_t tmpS[4] = {state[0][c], state[1][c], state[2][c], 
                                       state[3][c]};
                    
                    // MixColumns operation from AES proposal
                    uint8_t Tmp = (tmpS[0] ^ tmpS[1] ^ tmpS[2] ^ tmpS[3]);
                    uint8_t Tm =  (tmpS[0] ^ tmpS[1]) ; Tm = xtime(Tm); 
                    state[0][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[1] ^ tmpS[2]) ; Tm = xtime(Tm); 
                    state[1][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[2] ^ tmpS[3]) ; Tm = xtime(Tm);
                    state[2][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[3] ^ tmpS[0]) ; Tm = xtime(Tm);
                    state[3][c] ^=  (Tm ^ Tmp);
                }
                return state;
            }
            
        private:
            uint32_t sub_int(uint32_t y)
            {
                return sbox[(y&0xff)>>4][y&0x0fU];
            }
            
        public:
            uint32_t subword(uint32_t x)
            {
                return (sub_int(x>>24)<<24) | (sub_int((x>>16)&0xff)<<16) |
                       (sub_int((x>>8)&0xff)<<8) | (sub_int(x&0xff)); 
            }
            
            uint8_t** addroundkey(uint8_t** state, uint32_t* w, uint32_t rnd,
                                  uint8_t Nb)
            {
                for(int c=0;c<Nb;c++) {
                    uint32_t w_index = w[rnd*4+c];
                    state[0][c] ^= (w_index >> 24) & 0xff;
                    state[1][c] ^= (w_index >> 16) & 0xff;
                    state[2][c] ^= (w_index >> 8) & 0xff;
                    state[3][c] ^= w_index & 0xff;
                }
                return state;
            }
        
            /* DECRYPTION */
            
            uint8_t** inv_subBytes(uint8_t** state, uint8_t Nb)
            {
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = state[r][c] & 0x0fU;
                        uint8_t high_mask = state[r][c] >> 4;
                        state[r][c] = inv_sbox[high_mask][low_mask];
                    }
                }
                return state;
            }
            
            uint8_t** inv_shiftrows(uint8_t** state, uint8_t Nb)
            {
                // to stop values from overriding, duplicate matrix
               uint8_t inv_pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       inv_pre_state[r][c] = state[r][c];
               }
                

                // shift rows. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][(r+c)%4] = inv_pre_state[r][c];
                }
                return state;
            }
            
            uint8_t** inv_mixcolumns(uint8_t** state, uint8_t Nb)
            {
                uint8_t s_mixarr[4] = {0x0e, 0x0b, 0x0d, 0x09};
                for(int c=0;c<Nb;c++) {
                    // to stop matrix from overriding, use temporrary array
                    uint8_t tmp_state[4] = {state[0][c], state[1][c], state[2][c],
                                            state[3][c]};
                    state[0][c] = (GF256(tmp_state[0], s_mixarr[0]) ^
                                   GF256(tmp_state[1], s_mixarr[1]) ^
                                   GF256(tmp_state[2], s_mixarr[2]) ^
                                   GF256(tmp_state[3], s_mixarr[3]));
                    state[1][c] = (GF256(tmp_state[0], s_mixarr[3]) ^
                                   GF256(tmp_state[1], s_mixarr[0]) ^
                                   GF256(tmp_state[2], s_mixarr[1]) ^
                                   GF256(tmp_state[3], s_mixarr[2]));
                    state[2][c] = (GF256(tmp_state[0], s_mixarr[2]) ^
                                   GF256(tmp_state[1], s_mixarr[3]) ^
                                   GF256(tmp_state[2], s_mixarr[0]) ^
                                   GF256(tmp_state[3], s_mixarr[1]));
                    state[3][c] = (GF256(tmp_state[0], s_mixarr[1]) ^
                                   GF256(tmp_state[1], s_mixarr[2]) ^ 
                                   GF256(tmp_state[2], s_mixarr[3]) ^
                                   GF256(tmp_state[3], s_mixarr[0]));
                }
                return state;
            }
            
        protected:
           // KeyExpansion
           uint32_t* keyExpansion(std::shared_ptr<uint8_t> key, uint32_t* w, uint8_t Nb,
                                  uint8_t Nk, uint8_t Nr)
            {
                uint32_t temp;
                int i=0;
                do {
                    w[i] = ((uint32_t)key.get()[4*i]<<24) | (key.get()[4*i+1]<<16) |
                           (key.get()[4*i+2]<<8) | key.get()[4*i+3];
                    i++;
                } while(i<Nk);
                i=Nk;
                
                // rcon values. initialize twice so it doesn't override
                uint32_t tmp_rcon[11];
                for(int c=1;c<11;c++) {
                    tmp_rcon[c] = (uint8_t)(rcon[c] & 0xff)<<24;
                }
                
                while(i<Nb*(Nr+1)) {
                    temp = w[i-1];
                    if(i%Nk == 0) {
                        temp = subword(rotword(temp)) ^ (uint32_t)tmp_rcon[i/Nk];
                    }
                    else if(Nk>6 && i%Nk == 4) {
                        temp = subword(temp);
                    }
                    w[i] = temp ^ w[i-Nk];
                    i++;
                }
                return w;
            }
            
            uint8_t* cipher(uint8_t* input, uint8_t* output, uint32_t* w, 
                            uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // put 1-dimentional array values to a 2-dimentional matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                // call functions to manipulate state matrix
                addroundkey(state, w, 0, Nb);
                for(int rnd=1;rnd<Nr;rnd++) {
                    subBytes(state, Nb);
                    shiftrows(state, Nb);
                    mixcolumns(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                }
                subBytes(state, Nb);
                shiftrows(state, Nb);
                addroundkey(state, w, Nr, Nb);
            
                // copy state array to output
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                for(int c=0;c<4;c++) {
                   delete[] state[c];
                }
                delete[] state;
                return output;
            }
            
            std::string encrypt(std::string user_in,std::shared_ptr<uint8_t> key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare arrays
                uint8_t input[4*Nb];
                uint8_t output[4*Nb];
                uint32_t w[Nb*(Nr+1)]; // key schedule
                
                // append user input to 1-dimentional array
                for(int c=0;c<4*Nb;c++) {
                    input[c] = user_in[c];
                }
                
                // call KeyExpansion and Cipher function
                keyExpansion(key, w, Nb, Nk, Nr);
                cipher(input, output, w, Nb, Nk, Nr);

                // convert output array to hex string
                std::stringstream ss;
                for (int c=0;c<4*Nb;c++)
                {
                    ss << std::setfill('0') << std::setw(2) << std::hex
                       << (uint16_t)output[c];
                }
            	return ss.str();
            }
            
            uint8_t* invCipher(uint8_t* input, uint8_t* output, uint32_t* w,
                               uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix as a 2d C++ pointer
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // 1d input to 2d matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                addroundkey(state, w, Nr, Nb);
                for(int rnd=Nr-1;rnd>0;rnd--) {
                    inv_shiftrows(state, Nb);
                    inv_subBytes(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                    inv_mixcolumns(state, Nb);
                }
                
                inv_shiftrows(state, Nb);
                inv_subBytes(state, Nb);
                addroundkey(state, w, 0, Nb);
                
                // 2d array to 1d array
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                return output;
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare single-dimentional arrays
                uint8_t output[4*Nb];
                uint8_t input[4*Nb];
                uint32_t w[Nb*(Nr+1)];
                std::stringstream conv;
                for(int c=0;c<user_in.length();c+=2) {
                    conv << std::hex << user_in.substr(c,2);
                    int32_t uint8;
                    conv >> uint8;
                    input[c/2] = uint8 & 0xffU;
                    conv.str(std::string());
                    conv.clear();
                }
                
                // create key schedule and decrypt
                keyExpansion(key, w, Nb, Nk, Nr); 
                invCipher(input, output, w, Nb, Nk, Nr);
                std::string str = "";
                for(int c=0;c<4*Nb;c++) {
                    str += output[c];
                }
                return str;
            }
        public:
            std::string multi_block_process_enc(std::string user_in, std::shared_ptr<uint8_t>
                                                key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                // pad message so that length is a multiple of block size(16)
                uint32_t msg_blen = user_in.length() + 16-user_in.length()%16;
                if(user_in.length()%16 == 0) {
                    msg_blen-=16;
                }
                std::stringstream ss;
                ss << user_in << std::setfill('0') << std::setw(msg_blen) << "";
                std::string new_input[msg_blen/16];
                int32_t k=-1;
                std::string final_val = "";
                
                // seperate message into blocks of 16
                for(int c=0;c<msg_blen;c+=16) {
                    k++;
                    if(k<msg_blen/16) {
                        new_input[k] = ss.str().substr(c,16);
                    }
                }
                for(int c=0;c<msg_blen/16;c++) {
                    final_val += encrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
            
            std::string multi_block_process_dec(std::string user_in, std::shared_ptr
                                                <uint8_t> key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                std::string new_input[user_in.length()/32];
                int k=-1;
                std::string final_val = "";
                
                // input length has to be a multiple of 16 bytes
                if(user_in.length()%32 != 0) {
                    std::cout << "ERROR:\tlength is not a multiple of 32";
                    exit(EXIT_FAILURE);
                }
                
                // seperate message into blocks of 32 hex digits
                for(int c=0;c<user_in.length();c+=32) {
                    k++;
                    new_input[k] = user_in.substr(c,32);
                }
                k=user_in.length()/32;
                for(int c=0;c<k;c++) {
                    final_val += decrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
    };
    
    public:
    class AES128
    {
        // AES algorithm size for AES128
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 4;
            const uint8_t Nr = 10;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
    
    class AES192
    {
        // AES algorithm size for AES192
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 6;
            const uint8_t Nr = 12;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
        
    };
    
    class AES256
    {
        // AES algorithm size for AES256
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 8;
            const uint8_t Nr = 14;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
};





/*
 *  github: kibnakamoto
 *   Created on: Dec. 5, 2021
 *      Author: Taha Canturk
 *       Finalized: Jan. 5 2022
 *        More Info: github.com/kibnakamoto/sha512.cpp/blob/main/README.md
 */

#ifndef SHA512_H_
#define SHA512_H_

#include <string>
#include <cstring>
#include <stdint.h>
#include <memory>
#include <iomanip>

// choice = (x ∧ y) ⊕ (¯x ∧ z)
inline uint64_t Ch(uint64_t e, uint64_t f, uint64_t g) { return ((e bitand f)xor(~e bitand g)); }

// // majority = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
inline uint64_t Maj(uint64_t a, uint64_t b, uint64_t c) { return ((a & b)^(a & c)^(b & c)); }

// // binary operators
inline uint64_t Shr(uint64_t x, unsigned int n) { return (x >> n); }
inline uint64_t Rotr(uint64_t x, unsigned int n) { return ( (x >> n)|(x << (sizeof(x)<<3)-n) ); }


// length which is __uint128_t in 2 uint64_t integers
inline std::pair<uint64_t,uint64_t> to2_uint64(__uint128_t source) {
    constexpr const __uint128_t bottom_mask = (__uint128_t{1} << 64) - 1;
    constexpr const __uint128_t top_mask = ~bottom_mask;
    return {source bitand bottom_mask, Shr((source bitand top_mask), 64)};
}

class SHA512
{
    protected:
        // 80 64 bit unsigned constants for sha512 algorithm
        const uint64_t K[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
            0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
            0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
            0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 
            0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
            0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
            0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
            0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
            0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
            0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
            0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
            0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
            0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
            0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
        
        // initialize hash values
        uint64_t H[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                         0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
            
            // transform
            uint64_t* transform(uint64_t* TMP)
            {
                // initialize hash values
                uint64_t V[8];
                memcpy(V, H, sizeof(uint64_t)*8);

                // create message schedule
                for (int c=16;c<80;c++)
                {
                    // σ0 = (w[c−15] ≫≫ 1) ⊕ (w[c−15] ≫≫ 8) ⊕ (w[c−15] ≫ 7)
                    uint64_t s0 = Rotr(TMP[c-15],1) xor Rotr(TMP[c-15],8) xor 
                                       Shr(TMP[c-15],7);
                    
                    // σ1 = (w[c−2] ≫≫ 19) ⊕ (w[c−2] ≫≫ 61) ⊕ (w[c−2] ≫ 6)
                    uint64_t s1 = Rotr(TMP[c-2],19) xor Rotr(TMP[c-2],61) xor 
                                  Shr(TMP[c-2],6);
                    
                    // uint64_t does binary addition 2^64.
                    // w[c] = w[c−16] [+] σ0 [+] w[c−7] [+] σ1
                    TMP[c] = TMP[c-16] + s0 + TMP[c-7] + s1;
                }
                
                for (int c=0;c<80;c++)
                {
                    // Σ0 = (a ≫≫ 28) ⊕ (a ≫≫ 34) ⊕ (a ≫≫ 39)
                    uint64_t S0 = Rotr(V[0], 28) xor Rotr(V[0], 34) xor Rotr(V[0], 39);
                    
                    // T2 = Σ0 + Maj
                    uint64_t temp2 = S0 + Maj(V[0], V[1], V[2]);
                    
                    // Σ1 = (e ≫≫ 14) ⊕ (e ≫≫ 18) ⊕ (e ≫≫ 41)
                    uint64_t S1 = Rotr(V[4], 14) xor Rotr(V[4], 18) xor Rotr(V[4], 41);
                    
                    // T1 = h + Σ1 + Ch[e,f,g] + K[c] + W[c]
                    uint64_t temp1 = V[7] + S1 + Ch(V[4], V[5], V[6]) + K[c] + TMP[c];
                    
                    // modify hash values
                    V[7] = V[6];
                    V[6] = V[5];
                    V[5] = V[4];
                    V[4] = V[3] + temp1;
                    V[3] = V[2];
                    V[2] = V[1];
                    V[1] = V[0];
                    V[0] = temp1 + temp2;
                }
                for(int c=0;c<8;c++) {
                    H[c] += V[c];
                }

                return H;
            }
        
    public:
        std::shared_ptr<uint64_t> Sha512(std::string msg)
        {
        	// length in bytes.
            __uint128_t len = msg.length();
            
            // length is represented by a 128 bit unsigned integer
            __uint128_t bitlen = len << 3;
            
            // padding with zeros
            unsigned int padding = ((1024-(bitlen+1)-128) % 1024)-7; // in bits
            padding /= 8; // in bytes.
            __uint128_t blockBytesLen = padding+len+17;
            uint8_t WordArray[blockBytesLen];
            memset(WordArray, 0, blockBytesLen);
            for (__uint128_t c=0;c<len;c++) {
                WordArray[c] = msg.c_str()[c];
            }
            WordArray[len] = (uint8_t)0x80; // append 10000000.
            
            uint64_t W[blockBytesLen/8];
            // pad W with zeros
            for (int c=0;c<blockBytesLen/8;c++) {
                W[c] = 0x00;
            }
            /* TODO: convert to big endian so it works on all operating systems */
            
            // 8 bit array values to 64 bit array using 64 bit integer array.
            for (int i=0; i<len/8+1; i++) {
                W[i] = (uint64_t)WordArray[i*8]<<56;
                for (int j=1; j<=6; j++)
                    W[i] = W[i]|( (uint64_t)WordArray[i*8+j]<<(7-j)*8);
                W[i] = W[i]|( (uint64_t)WordArray[i*8+7] );
            }
            
            // append 128 bit length as 2 uint64_t's as a big endian
            auto [fst, snd] = to2_uint64(bitlen);
            W[Shr(padding+len+1,3)+1] = fst;
            W[Shr(padding+len+1,3)+2] = snd;
            
            /* multi-block processing start */
            uint64_t TMP[80];
            for(int c=0;c<80;c++) {
                TMP[c] = 0x00;
            }
            
            // multi-block and single block processing
            for(int c=0;c<blockBytesLen/128;c++) {
                for(int i=0;i<16;i++)
                    TMP[i] = W[i+16*c];
                transform(TMP);
            }
            // convert raw pointer to shared_ptr
            std::shared_ptr<uint64_t> shared_H(new uint64_t[8]);
            for(int c=0;c<8;c++) {
                shared_H.get()[c] = H[c];
            }
        	return shared_H;
        }
        
        // for hashing 2 uint64_t pointer hashes. For MerkleTree
        std::shared_ptr<uint64_t> sha512_ptr(std::shared_ptr<uint64_t> hash1, 
                                             std::shared_ptr<uint64_t> hash2)
        {
            IntTypes int_type = IntTypes();
            uint64_t W[32];
            uint64_t TMP[80];
            for(int c=0;c<80;c++) {
                TMP[c] = 0x00;
            }
            for(int c=16;c<32;c++) {
                W[c] = 0x00;
            }
            
            alignas(uint8_t) std::shared_ptr<uint8_t> wordArray(new uint8_t[128]);
            wordArray = int_type.arr64ToCharArr(hash1, hash2);
            
            // 8 bit array values to 64 bit array using 64 bit integer array
            for(int i=0;i<128/8;i++) {
                W[i] = (uint64_t)wordArray.get()[i*8]<<56;
                for(int j=1;j<=6;j++)
                    W[i] = W[i]|( (uint64_t)wordArray.get()[i*8+j]<<(7-j)*8);
                W[i] = W[i]|( (uint64_t)wordArray.get()[i*8+7] );
            }
            
            // append 1 as 64-bit value
            W[16] = 0x80ULL<<56;
            
            // append bitlen
            W[32-1] = 0x400ULL;
            
            // multi-block processing
            for(int c=0;c<2;c++) {
                for(int i=0;i<16;i++)
                    TMP[i] = W[i+16*c]; // 16 indexes = 1 block of data
                transform(TMP);
            }
            
            // convert raw pointer to shared_ptr
            std::shared_ptr<uint64_t> shared_H(new uint64_t[8]);
            for(int c=0;c<8;c++) {
                shared_H.get()[c] = H[c];
            }
            return shared_H;
        }
        
        std::shared_ptr<uint64_t> sha512_single_ptr(std::shared_ptr<uint64_t>
                                                    singleHash)
        {
            uint64_t W[80];
            for(int c=9;c<80;c++) {
                W[c] = 0x00;
            }
            
            /* to avoid hash smaller than 512-bit (e.g. 511-bit) to be rehashed
             * with no leading zeros. But might be unnecessary.
             */
            std::shared_ptr<uint8_t> wordArray(new uint8_t[64]);
            for(int c=0;c<8;c++) {
                for(int i=56,k=0;i>=0,k<8;i-=8,k++) {
                    wordArray.get()[c*8+k] = singleHash.get()[c]>>i & 0xff;
                }
            }
            
            // put orginized bytearray into 64-bit W array
            for (int i=0;i<64/8;i++) {
                W[i] = (uint64_t)wordArray.get()[i*8]<<56;
                for (int j=1;j<=6;j++)
                    W[i] = W[i]|( (uint64_t)wordArray.get()[i*8+j]<<(7-j)*8);
                W[i] = W[i]|( (uint64_t)wordArray.get()[i*8+7] );
            }
            
            // append 1 as 64-bit value
            W[8] = 0x80ULL<<56;
            
            // append bitlen
            W[16-1] = 0x200ULL;
            
            // single-block transform
            transform(W);
            
            // convert raw pointer to shared_ptr
            std::shared_ptr<uint64_t> shared_H(new uint64_t[8]);
            for(int c=0;c<8;c++) {
                shared_H.get()[c] = H[c];
            }
            return shared_H;
        }
};

std::shared_ptr<uint64_t> sha512(std::string input) {
    SHA512 hash;
    return hash.Sha512(input);
}

std::string sha512_str(std::string input) {
    std::stringstream ss;
    for (int c=0;c<8;c++) {
        ss << std::setfill('0') << std::setw(16) << std::hex
           << (sha512(input).get()[c]|0);
    }
	return ss.str();
}

#endif /* SHA512_H_ */




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
                    /* nodes are single a layer of the MerkleTree */
                    return nodes;
                }
            public:
                std::shared_ptr<uint64_t> append_levels(std::vector<std::shared_ptr
                                                        <uint64_t>> mempool, 
                                                        uint64_t len, std::
                                                        shared_ptr<uint64_t>
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
                    }
                    return merkle_root;
                }
        };
        
        inline std::shared_ptr<uint64_t> merkleRoot(std::vector<std::shared_ptr
                                                    <uint64_t>> Mempool)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            Node node = Node();
            
            // declare merkle root
            alignas(uint64_t) std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            
            // to avoid 0 hashes to be invalid transactions in Mempool
            std::vector<std::shared_ptr<uint64_t>> mempool = Mempool;
            
            uint64_t len = mempool.size(); // amount of transactions in the block
            uint64_t validlen = 2;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                std::shared_ptr<uint64_t> oddZfill(new uint64_t[8]);
                
                // TODO: convert "00000000" to memset("", "0", validlen); in future version
                oddZfill = sha512("00000000"); 
                mempool.push_back(oddZfill);
                len++; // update len
            }
            
            // calculate amount of layers
            while(validlen != 0) {
                validlen/=2;
                /* validlen gets set to zero so don't use it after this loop */
            }
            // calculate Merkle Root
            merkle_root = node.append_levels(mempool, len, merkle_root);
            return merkle_root;
        }
}; // namespace MerkleTree



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
    
    template<class T>
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
                while(target.get()[c] > pow(2,62)) { // define target hash
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
                  v_merkle_root, std::vector<uint64_t> trnsLengths)
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
            
            /* TODO: use difficulty to generate target height instead of const 2 to 
             * the power of 56. NOTE: Block generation time = 1-2 minutes.
             */
            for(int c=0;c<8;c++) {
                while(target.get()[c] >= pow(2,56)) {
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
        //     std::stringstream BLOCKCHAIN_BLOCKDATA;
        //     std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
        //     std::string timestamp;
        //     uint32_t blockchainSize;
        //     uint64_t nonce;
        //     double difficulty, nextBlockGenTime, avHashrate;
        //     std::shared_ptr<uint64_t> merkle_root;
        //     std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
        //              merkle_root,nextBlockGenTime, avHashrate) = block_data;
        //     BLOCKCHAIN_BLOCKDATA << "previous block hash: ";
        //     for(int c=0;c<8;c++) {
        //         BLOCKCHAIN_BLOCKDATA << std::hex
        //                              << prevBlockHash.get()[c];
        //     }
        //     BLOCKCHAIN_BLOCKDATA << "\ntimestamp: " << timestamp;
        //     BLOCKCHAIN_BLOCKDATA << "blockchain size: "
        //                          << std::dec << blockchainSize;
        //     BLOCKCHAIN_BLOCKDATA << "\nnonce: "
        //                          << std::dec << nonce;
        //     BLOCKCHAIN_BLOCKDATA << "\ndifficulty: "
        //                          << difficulty;
        //     BLOCKCHAIN_BLOCKDATA << "\nmerkle_root: ";
        //     for(int c=0;c<8;c++) {
        //         BLOCKCHAIN_BLOCKDATA << std::hex << merkle_root.get()[c];
        //     }
        //     BLOCKCHAIN_BLOCKDATA << "\napproximate time until next block: "
        //                          << nextBlockGenTime;
        //     BLOCKCHAIN_BLOCKDATA << "\nAverage hashrate of miners: "
        //                          << avHashrate;
        //     BLOCKCHAIN_BLOCKDATA << "\nblockchain version: " << blockchain_version;
        //     std::shared_ptr<uint64_t> blockHash;
        //     blockHash = sha512(BLOCKCHAIN_BLOCKDATA.str());
        //     BLOCKCHAIN_BLOCKDATA << "\nblock hash: ";
        //     for(int c=0;c<8;c++) {
        //         BLOCKCHAIN_BLOCKDATA << std::hex << blockHash.get()[c];
        //     }
        //     Blockchain::Blockhashes.push_back(blockHash);
        //     Blockchain::blockchain.push_back(BLOCKCHAIN_BLOCKDATA.str());
        //     return BLOCKCHAIN_BLOCKDATA.str();
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
            std::stringstream BLOCKCHAIN_BLOCKDATA;
            std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]);
            merkle_root = MerkleTree::merkleRoot(clean_mempool);
            BLOCKCHAIN_BLOCKDATA << "previous block hash: ";
            for(int c=0;c<8;c++) {
                BLOCKCHAIN_BLOCKDATA << std::hex
                                     << prevBlockHash.get()[c];
            }
            BLOCKCHAIN_BLOCKDATA << "\ntimestamp: " << timestamp;
            BLOCKCHAIN_BLOCKDATA << "blockchain size: "
                                 << std::dec << blockchainSize;
            BLOCKCHAIN_BLOCKDATA << "\nnonce: "
                                 << std::dec << nonce;
            BLOCKCHAIN_BLOCKDATA << "\ndifficulty: "
                                 << difficulty;
            BLOCKCHAIN_BLOCKDATA << "\nmerkle_root: ";
            for(int c=0;c<8;c++) {
                BLOCKCHAIN_BLOCKDATA << std::hex << merkle_root.get()[c];
            }
            BLOCKCHAIN_BLOCKDATA << "\napproximate time until next block: "
                                 << nextBlockGenTime;
            BLOCKCHAIN_BLOCKDATA << "\nAverage hashrate of miners: "
                                 << avHashrate;
            BLOCKCHAIN_BLOCKDATA << "\nblockchain version: " << blockchain_version;
            std::shared_ptr<uint64_t> blockHash;
            blockHash = sha512(BLOCKCHAIN_BLOCKDATA.str());
            BLOCKCHAIN_BLOCKDATA << "\nblock hash: ";
            for(int c=0;c<8;c++) {
                BLOCKCHAIN_BLOCKDATA << std::hex << blockHash.get()[c];
            }
            Blockchain::Blockhashes.push_back(blockHash);
            Blockchain::blockchain.push_back(BLOCKCHAIN_BLOCKDATA.str());
            return BLOCKCHAIN_BLOCKDATA.str();
        }
};



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
            std::cout << std::endl << std::endl << "AES256 key 1:\t {";
            for(int c=0;c<32;c++) {
                std::cout << "0x" << std::hex << (short)val[0].get()[c];
                if(c<31) {
                    std::cout << ", ";
                }
            }
            
            std::cout << std::endl << std::endl << "AES256 key 2:\t {";
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
                std::cout << std::endl << "AES256 key 1:\t";
                for(int c=0;c<32;c++) {
                    std::cout << (short)AESkey.get()[c] << " ";
                }
                std::cout << std::endl << std::endl;
                std::cout << "AES256 key 2:\t";
                for(int c=0;c<32;c++) {
                    std::cout << (short)NewAESkey.get()[c] << " ";
                }
                std::cout << std::endl << std::endl;

            }
            std::vector<std::shared_ptr<uint8_t>> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {sha512(AES256_ciphertext), keys};
        }
        
        // for UI input
        void verifyInputWallet(std::vector<std::shared_ptr<uint64_t>> walletAddresses,
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
                    std::cout << "\nerror: wrong wallet address";
                    exit(EXIT_FAILURE);
                }
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

/* UI */
struct userData
{
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
    std::map<std::string,std::shared_ptr<uint8_t>> &transactions;
    std::vector<std::shared_ptr<uint64_t>> &transactionhashesW;
    std::vector<int32_t> &trnsLengths;
    
    int32_t setBalance()
    {
        std::string plaintext;
        AES::AES256 aes256;
        int32_t storedCrypto=0;
        for(auto const [ciphertext, b32key] : transactions) {
            plaintext = aes256.decrypt(ciphertext,b32key);
            std::string str_amount = "";
            size_t index = plaintext.find("amount: ");
            int lenIndex;
            
            // delete padding caused by encryption
            // check which length creates correct hash
            for(int c=0;c<trnsLengths.size();c++) {
                plaintext.erase(trnsLengths[c],plaintext.length()-trnsLengths[c]);
                std::shared_ptr<uint64_t> hash = sha512(plaintext);
                for(int i=0;i<transactionhashesW.size();i++) {
                    for(int j=0;j<8;j++)
                        if(transactionhashesW[i].get()[j] == hash.get()[j]) {
                            lenIndex = c;
                            goto stop;
                        }
                }
                stop:
                    for(int k=lenIndex;k<plaintext.length();k++) {
                        str_amount += plaintext[k];
                    }
                    int32_t amount = static_cast<int32_t>(std::stoul(str_amount));
                    storedCrypto += amount;
            }
        }
        return storedCrypto;
    }
};

/* UI */
struct userDatabase : public userData
{
    
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
                                             "enc-algs", "start mine", "end mine",
                                             "dump-wallet512", "dump-w-aes256k", "get tr-target",
                                             "get tr-hash", "get tr-ciphertext",
                                             "get tr-timestamp", "dump all-trnsData",
                                             "dump trnsData", "get blockchain-ahr",
                                             "get block-target"};
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
     "start mine: start mining", "end mine: end mining",
     "dump-wallet512: dump 512-bit wallet address as decimal",
     "dump-w-aes256k: dump 32 byte wallet key", // after this is not in version 1
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
    std::map<std::string,std::shared_ptr<uint8_t>> transactions;
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
    itWalletMap = walletMap.begin();
    std::vector<std::shared_ptr<uint8_t>> userAESmapkeys;
    std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
    std::vector<int32_t> trnsLengths;
    
    
    // transaction list in wallet
    std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
    
    std::shared_ptr<uint64_t> secondWallet(new uint64_t[8]);
    
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
        std::cout << std::endl << "wallet address as decimal, for use in UI: ";
        for(int c=0;c<8;c++)
            std::cout << std::dec << walletAddress.get()[c] << " ";
        std::cout << std::endl << "save these values on your device\n";
        walletAddresses.push_back(walletAddress);
        walletMap.insert(itWalletMap, std::pair<std::shared_ptr<uint64_t>,
                         std::vector<std::shared_ptr<uint8_t>>>(walletAddress,
                                                                sndNewAddrs));
        std::cout << "wallet address saved on map\n";
    }
    else if(userInput == "buy" || userInput == "sell") {
        uint32_t amount;
        int32_t storedCrypto;
        // ask for walletAddress of receiver or seller, key isn't requiried
        if(userInput == "buy") {
            if(walletMap.empty()) { // Don't use: else Use \"dump-wallet512\" and copy paste
                std::cout << "wallet map is empty, input your wallet address."
                          <<"If you don\'t have one, type \"nw \" here,press enter, "
                          << "if you have one, press enter, copy paste wallet address"
                          << "from where you saved it as decimal with whitespaces:\t";
                std::string noWallet;
                std::cin >> noWallet;
                if(noWallet == "yw") {
                    for(int c=0;c<8;c++)
                        std::cin >> walletAddress.get()[c];
                    
                    // verify inputted wallet
                    wallet_address.verifyInputWallet(walletAddresses, walletAddress);
                    
                    // if walletAddress valid, input wallet keys
                    std::cout << "\ninput your aes256 wallet key 1 (don\'t "
                              << "delete white spaces in between numbers):\t";
                    for(int c=0;c<32;c++)
                        std::cin >> userAESmapkeys[0].get()[c];
                    std::cout << "\ninput your aes256 wallet key 2 (don\'t "
                              << "delete white spaces in between numbers):\t";
                    for(int c=0;c<32;c++)
                        std::cin >> userAESmapkeys[1].get()[c];

                    walletMap.insert(itWalletMap, std::pair<std::shared_ptr<uint64_t>, 
                                     std::vector<std::shared_ptr<uint8_t>>>
                                     (walletAddress, userAESmapkeys));
                    struct Wallet trWallet{walletAddress, userAESmapkeys, walletMap};
                    std::cout << "\ninput senders wallet address:\t";
                    for(int c=0;c<8;c++)
                        std::cin >> secondWallet.get()[c];
                    wallet_address.verifyInputWallet(walletAddresses, walletAddress);
                    std::cout << "\nwallet data verified and saved\n";
                    std::cout << "\ninput amount:\t";
                    std::cin >> amount;
                    struct userData user_data {walletMap,transactions,transactionhashesW,
                                               trnsLengths};
                    storedCrypto = user_data.setBalance();
                    auto [Fst,Snd] = trWallet.new_transaction(secondWallet,walletAddress,
                                                                amount,mempool,
                                                                "buy", transactionhashesW,
                                                                transactions, 
                                                                storedCrypto,
                                                                "dump aes256-key");

                    
                } else {// only difference is first trWallet parameter is nullptr
                    storedCrypto=0;
                    struct Wallet trWallet{nullptr, userAESmapkeys, walletMap};
                    
                    std::cout << "\ninput senders wallet address:\t";
                    for(int c=0;c<8;c++)
                        std::cin >> secondWallet.get()[c];
                    wallet_address.verifyInputWallet(walletAddresses, walletAddress);
                    std::cout << "\nwallet data saved\n";
                    std::cout << "\ninput amount:\t";
                    std::cin >> amount;
                    struct userData user_data {walletMap,transactions,transactionhashesW,
                                               trnsLengths};
                    storedCrypto = user_data.setBalance();
                    auto [Fst,Snd] = trWallet.new_transaction(secondWallet,walletAddress,
                                                                amount,mempool,
                                                                "buy", transactionhashesW,
                                                                transactions, 
                                                                storedCrypto,
                                                                "dump aes256-key");

                }
            }
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
