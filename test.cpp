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
           uint32_t* keyExpansion(uint8_t* key, uint32_t* w, uint8_t Nb,
                                  uint8_t Nk, uint8_t Nr)
            {
                uint32_t temp;
                int i=0;
                do {
                    w[i] = ((uint32_t)key[4*i]<<24) | (key[4*i+1]<<16) |
                           (key[4*i+2]<<8) | key[4*i+3];
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
            
            std::string encrypt(std::string user_in,uint8_t* key, uint8_t Nb,
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
            
            std::string decrypt(std::string user_in, uint8_t* key, uint8_t Nb,
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
                invCipher(input, output, w, Nb, Nk, Nr); // output wrong 
                std::string str = "";
                for(int c=0;c<4*Nb;c++) {
                    str += output[c]; /* Check invCipher */
                }
                return str;
            }
        public:
            std::string multi_block_process_enc(std::string user_in, uint8_t*
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
            
            std::string multi_block_process_dec(std::string user_in, uint8_t* 
                                                key, uint8_t Nb, uint8_t Nk,
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
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
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
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
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
            std::string encrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, uint8_t* key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
};





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
            for(int c=0;c<16;c++) {
                hashchArr.get()[c*8] = hashArr.get()[c]>>56 & 0xff;
                hashchArr.get()[c*8+1] = hashArr.get()[c]>>48 & 0xff;
                hashchArr.get()[c*8+2] = hashArr.get()[c]>>40 & 0xff;
                hashchArr.get()[c*8+3] = hashArr.get()[c]>>32 & 0xff;
                hashchArr.get()[c*8+4] = hashArr.get()[c]>>24 & 0xff;
                hashchArr.get()[c*8+5] = hashArr.get()[c]>>16 & 0xff;
                hashchArr.get()[c*8+6] = hashArr.get()[c]>>8 & 0xff;
                hashchArr.get()[c*8+7] = hashArr.get()[c] & 0xff;
            }
            return hashchArr;
        }
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
            for (int c=0; c<blockBytesLen/8; c++) {
                W[c] = 0x00;
            }
            
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
            
            // for(int c=0;c<8;c++) {
            //     W[c] = hash1.get()[c];
            //     W[c+8] = hash2.get()[c];
            // }
            std::shared_ptr<uint8_t> wordArray(new uint8_t[128]);
            wordArray = int_type.arr64ToCharArr(hash1, hash2);
            
            // 8 bit array values to 64 bit array using 64 bit integer array.
            for (int i=0;i<16/8+1;i++) {
                W[i] = (uint64_t)wordArray.get()[i*8]<<56;
                for (int j=1;j<=6;j++)
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
            for(int c=0;c<8;c++) {
                W[c] = singleHash.get()[c];
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
           cryptography but couldn't find a cryptographic random byte generator */
        std::random_device randDev;
        std::mt19937 generator(randDev() ^ time(NULL));
        std::uniform_int_distribution<T> distr;
        return distr(generator);
    }
    
    inline double difficulty(uint64_t nonce)
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
        {
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
        double timeM = difficulty * pow(2,32) / hashrate / 3600; // minutes
        return timeM;
    }
};

class PoW
{
    protected:
        bool mineSingleTr(std::string encryptedTr, uint8_t* key, uint64_t
                          difficulty, std::vector<std::shared_ptr<uint64_t>>
                          mempool, uint64_t nonce, std::shared_ptr<uint64_t> target)
        {
            std::cout << "calculating target...\n";
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            uint64_t newNonce = nonce;
            for(int c=0;c<8;c++) {
                while(target.get()[c] > pow(2,30)) { // define target hash
                    target.get()[c] = sha512(encryptedTr +
                                       std::to_string(newNonce+difficulty)).get()[c];
                    newNonce++;
                }
            }
            // verify transaction data
            std::cout << "verifying transaction...\n";
            AES::AES256 aes256;
            std::string transactionData = aes256.decrypt(encryptedTr, key);
            std::shared_ptr<uint64_t> hash(new uint64_t);
            hash = sha512(transactionData);
            bool valid;
            if(std::find(mempool.begin(), mempool.end(), hash) != mempool.end()) {
                valid = true;
            } else {
                valid = false;
            }
            std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
            std::cout << "seconds it took to verify transaction: "
                      << std::chrono::duration_cast<std::chrono::microseconds>
                         (end - begin).count()
                      << std::endl;
            return valid;
        }
    public:
        bool mineBlock(const std::map<std::string, uint8_t*> encryptedTs,
                       uint64_t blockNonce, uint64_t difficulty, 
                       std::vector<std::shared_ptr<uint64_t>> mempool, std::shared_ptr<uint64_t>
                       v_merkle_root)
        {
            std::shared_ptr<uint64_t> target(new uint64_t); // each index >= 2^30
            uint64_t loopt = 0;
            std::shared_ptr<uint64_t> merkle_root;
            MerkleTree::merkleRoot(mempool, merkle_root);
            if(merkle_root != v_merkle_root) {
                std::cout << "\nmerkle_root: false\n\n";
                for (auto const& [key, val] : encryptedTs) {
                    bool v = mineSingleTr(key, val, difficulty, mempool,
                                          blockNonce, target);
                    if(v == false) {
                        std::cout << "transaction hash mismatch, transaction index:\t"
                                  << loopt << "\n" << "transaction hash:\n";
                        for(int c=0;c<8;c++) {
                            std::cout << std::hex << mempool[loopt].get()[c];
                        }
                        std::cout << std::endl;
                        mempool.erase(mempool.begin() + loopt);
                        std::cout << "\ntransaction deleted from mempool\n";
                        
                        loopt++; // mempool index
                    } else {
                        std::cout << "validated transaction:\t" << loopt
                                  << " from mempool\n";
                    }
                }
            } else {
                std::cout << "\nmerkle_root: true\n\n";
            }
            return true;
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
        void genBlock(std::shared_ptr<uint64_t> target, uint64_t nonce, std::shared_ptr<uint64_t>
                      merkle_root, double difficulty)
        {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            bool valid;
            uint64_t newNonce = nonce;
            std::string merkle_root_str = "";
            for(int c=0;c<8;c++) {
                merkle_root_str += std::to_string(merkle_root.get()[c]);
            }
            
            for(int c=0;c<8;c++) {
                while(target.get()[c] > pow(2,30)) {
                    target.get()[c] = sha512(merkle_root_str +
                                             std::to_string(newNonce+difficulty)).get()[c];
                    newNonce++;
                }
            }
            std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
            std::cout << "seconds it took to generate block: " << std::chrono::duration_cast
                                             <std::chrono::microseconds>
                                             (end - begin).count() << std::endl;
        }
        /* make a tuple function that returns block components */
        std::tuple</* prevBlockHash */std::shared_ptr<uint64_t>, 
                   /* timestamp */std::string, /* blockchain size */ uint32_t,
                   /* nonce */uint64_t, /* block difficulty */double,
                   /* merkle_root */std::shared_ptr<uint64_t>,
                   /* next block generation time*/double,
                   /* average hashrate */double, /* block hash */std::shared_ptr<uint64_t>>
       data(std::vector<std::shared_ptr<uint64_t>> mempool, const std::map<
            std::string, uint8_t*> encryptedTs, std::string encryptedTr="",
            uint8_t* AESkey=nullptr)
       {
           return {nullptr,"",0,0,0.0,nullptr,0.0,0.0, nullptr};
       }
        
        std::string data_str(std::vector<std::shared_ptr<uint64_t>> mempool, const 
                         std::map<std::string, uint8_t*> encryptedTs,
                         std::string encryptedTr="", uint8_t* AESkey=nullptr)
        {
            /* use this to represent block in blockchain */
            SHA512 hash = SHA512();
            PoW ProofofWork = PoW();
            std::shared_ptr<uint64_t> target(new uint64_t);
            std::shared_ptr<uint64_t> merkle_root;
            MerkleTree::merkleRoot(mempool, merkle_root);
            MerkleTree::merkleRoots.push_back(merkle_root);
            std::shared_ptr<uint64_t> prevBlockHash(new uint64_t);
            uint32_t blockchainsize = Blockchain::blockchain.size();
            std::string timestamp = Blockchain::generateTimestamp();
            uint64_t nonce = Blockchain::generateNonce<uint64_t>();
            uint64_t randHashNonce = Blockchain::generateNonce<uint64_t>();
            double difficulty = Blockchain::difficulty(randHashNonce);
            uint64_t hashrate = Blockchain::calcHashRateSha512(5); // accuracy=5
            hashrates.push_back(hashrate);
            uint64_t avHashrate = averageHashRate();
            std::cout << "\ngenerating block\n";
            genBlock(target, nonce, merkle_root, difficulty);
            bool blockMined = ProofofWork.mineBlock(encryptedTs, nonce, difficulty,
                                                    mempool, merkle_root);
            double blockGenTime = Blockchain::nextBlockTime(difficulty, avHashrate);
            std::cout << "next block will be generated in " << blockGenTime
                      << std::endl;
            if(blockchainsize > 1) {
                prevBlockHash = Blockchain::Blockhashes[blockchainsize-1];
            }
            return std::string();
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
#include "AES.h" // Symmetrical Encryption
#include "block.h"

// 256-bit random number. AES key
uint8_t* GenerateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    uint8_t* key = nullptr;
    key = new uint8_t[32];
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
      std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<32-4;c++) {
        uint32_t tmp = distr(generator);
        key[c] = tmp>>24 & 0xff;
        key[c+1] = tmp>>16 & 0xff;
        key[c+2] = tmp>>8 & 0xff;
        key[c+3] = tmp & 0xff;
    }
    return key;
}


struct Transaction {
    std::shared_ptr<uint64_t> sender;
    std::shared_ptr<uint64_t> receiver;
    uint32_t amount;
    
    std::string encryptTr(uint8_t* key)
    { // decrypted hashed data should equal hash in mempool. TEST
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
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<std::shared_ptr<uint64_t>,std::vector<uint8_t*>>
                    walletData)
    {/* not tested */
        /* walletData = map to verify if owner of the wallet is requesting data dump
           std::shared_ptr<uint64_t> is WalletAddress and vector of uint8_t* is the string AES key
           used as plain text and the AES key used as an AES key.
           walletData vector has length 2 and key used as key is first and 
           string key as uint8_t* is second
        */
        // useless function. Delete if not useful as reference
        std::cout << std::endl << std::endl;
        AES::AES256 aes256;
        std::string AESkeyStr = "";
        std::string AES256_ciphertext = "";
        for (auto const& [key, val] : walletData) {
            for(int c=0;c<32;c++) {
            AESkeyStr += std::to_string(val[1][c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
            for(int i=0;i<8;i++) {
                if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                    std::cout << "wallet Data mismatch";
                    exit(EXIT_FAILURE);
                }
            }
            std::cout << std::endl << std::endl << "AES256 key:\t";
            for(int c=0;c<32;c++) {
                std::cout << val[1][c];
            }
            std::cout << std::endl << std::endl;
        }
        std::cout << "sender\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << sender.get()[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "receiver\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << receiver.get()[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "amount:\t" << amount;
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
        std::pair<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        {
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            AES::AES256 aes256;
            uint8_t* AESkey = nullptr;
            AESkey = new uint8_t[32];
            AESkey = GenerateAES256Key(); // 32 bytes
            uint8_t* NewAESkey = nullptr;
            NewAESkey = new uint8_t[32];
            NewAESkey = GenerateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump AES-key") {
                std::cout << std::endl << "AES256 key:\t";
                for(int c=0;c<32;c++) {
                    std::cout << AESkey[c];
                }
                std::cout << std::endl << std::endl;
            }
            std::vector<uint8_t*> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {sha512(AES256_ciphertext), keys};
        }
};

class Address
{
    public:
        void verifyOwnerData(const std::map<std::shared_ptr<uint64_t>,
                             std::vector<uint8_t*>> walletData)
        {
            AES::AES256 aes256;
            std::string AESkeyStr = "";
            std::string AES256_ciphertext = "";
            for (auto const& [key, val] : walletData) {
                for(int c=0;c<32;c++) {
                    AESkeyStr += std::to_string(val[1][c]);
                }
                AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
                for(int i=0;i<8;i++) {
                    if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                        std::cout << "\nwallet data mismatch";
                        exit(EXIT_FAILURE);
                    } else {
                        std::cout << "\n\nwallet data verified\n\n";
                    }
                }
            }
        }
        
        void WalletAddressNotFound(std::shared_ptr<uint64_t> walletAddress,
                                   std::vector<uint8_t*> AESkeysWallet,
                                   std::string askForPrivKey="")
        {
            WalletAddress wallet_address = WalletAddress();
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
            
        }

        // if new transaction added to the Wallet
        void newTransaction(std::shared_ptr<uint64_t> sender,
                            std::shared_ptr<uint64_t> receiver, 
                            uint32_t amount, std::vector<std::shared_ptr<
                            uint64_t>> mempool, std::map<std::shared_ptr
                            <uint64_t>, std::vector<uint8_t*>> verifyInfo,
                            std::string sellorbuy, std::vector<uint8_t*> AESkeysTr,
                            std::vector<std::shared_ptr<uint64_t>> transactionhashes,
                            std::vector<std::string> ciphertexts, int32_t storedCrypto,
                            std::vector<uint8_t*> AESkeysWallet, std::shared_ptr
                            <uint64_t> walletAddress=nullptr,
                            std::string askForPrivKey="")
        {
            Address address = Address();
            if(walletAddress != nullptr) {
                verifyOwnerData(verifyInfo);
                if(sellorbuy=="sell") {
                    if(amount > storedCrypto) {
                        std::cout << "you do not own " << amount << ". Process failed";
                        exit(EXIT_FAILURE);
                    } else {
                        storedCrypto -= amount;
                    }
                } else if(sellorbuy=="buy") {
                    storedCrypto += amount;
                }
                struct Transaction trns{sender, receiver, amount};
                transactionhashes.push_back(trns.Hash());
                uint8_t* newAES_TrKey = nullptr;
                newAES_TrKey = new uint8_t[32];
                newAES_TrKey = GenerateAES256Key();
                ciphertexts.push_back(trns.encryptTr(newAES_TrKey));
                AESkeysTr.push_back(newAES_TrKey);
                mempool.push_back(transactionhashes[transactionhashes.size()]);
            } else {
                std::cout << "\nERR:\tWalletAddressNotFound\n";
                WalletAddressNotFound(walletAddress, AESkeysWallet, askForPrivKey);
                std::cout << "\nNew Wallet Address Created";
                newTransaction(sender, receiver, amount, mempool, verifyInfo,
                               sellorbuy, AESkeysTr, transactionhashes,
                               ciphertexts, storedCrypto, AESkeysWallet, nullptr);
                std::cout << "\nTransaction complete" << std::endl << std::endl;
            }
        }
};

struct Wallet {
    /* parameters to verify when owner of the wallet is modifying */
    // should be nullptr if WalletAddressNotFound
    std::shared_ptr<uint64_t> walletAddress;
    
    // can be empty if WalletAddressNotFound
    std::vector<uint8_t*> AESkeysWallet;  // length of 2
    
    /* verifyInfo includes AESkeysWallet in the first and second index. 
      If they don't match, don't change anything on the Wallet */
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> verifyInfo;
    void new_transaction(std::shared_ptr<uint64_t> sender,
                            std::shared_ptr<uint64_t> receiver, 
                            uint32_t amount, std::vector<std::shared_ptr<
                            uint64_t>> mempool, std::string sellorbuy,
                            std::vector<uint8_t*> AESkeysTr, std::vector<
                            std::shared_ptr<uint64_t>> transactionhashes,
                            std::vector<std::string> ciphertexts, int32_t
                            storedCrypto, std::string askForPrivKey="")

    {
        Address address = Address();
        address.newTransaction(sender, receiver, amount, mempool, verifyInfo, 
                               sellorbuy, AESkeysTr, transactionhashes, 
                               ciphertexts, storedCrypto, AESkeysWallet,
                               walletAddress, askForPrivKey);
    }
    void verifyOwnerData()
    {
        Address address = Address();
        address.verifyOwnerData(verifyInfo);
    }
    
    void WalletAddressNotFound(std::string askForPrivKey="")
    {
        Address address = Address();
        address.WalletAddressNotFound(walletAddress, AESkeysWallet, askForPrivKey);
    }
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
    struct Transaction trns{sha512("sender"), sha512("receiver"), 50000};
    struct Transaction trns1{sha512("sener"), sha512("receiver"), 54000};
    struct Transaction trns2{sha512("sender"), sha512("reciver"), 35600};
    struct Transaction trns3{sha512("nder"), sha512("receiver"), 50000};
    struct Transaction trns4{sha512("sender"), sha512("receiver"), 40000};
    mempool.push_back(trns.Hash());
    /* TEST MERKLE_ROOT */
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 5 transactions
    mempool.push_back(trns.Hash());
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash()); // 8 transactions
    /* TEST MERKLE_ROOT */
    /* TEST PoW MINE */
    uint8_t* AES_key_mining = new uint8_t[32];
    uint8_t* AES_key_mining1 = new uint8_t[32];
    uint8_t* AES_key_mining2 = new uint8_t[32];
    uint8_t* AES_key_mining3 = new uint8_t[32];
    AES_key_mining = GenerateAES256Key();
    AES_key_mining1 = GenerateAES256Key();
    AES_key_mining2 = GenerateAES256Key();
    AES_key_mining3 = GenerateAES256Key();
    std::map<std::string, uint8_t*> transactionsEnc;
    std::map<std::string, uint8_t*>::iterator it = transactionsEnc.begin();
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns3.encryptTr(AES_key_mining3), AES_key_mining3)); // 3

    /* TEST PoW MINE */
    // block.data(mempool, transactionsEnc);
    // MerkleTree::merkleRoot(mempool, merkle_root);
    auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    walletAddress = fst;
    walletAddresses.push_back(fst);
    std::cout << "\n\nline 339, main.cpp:\t";
    std::shared_ptr<uint64_t> TMPa = sha512("a");
    std::shared_ptr<uint64_t> TMPb = sha512("b");
    for(int c=0;c<8;c++) {
        for(int i=0;i<8;i++) {
            // std::cout << std::hex << walletAddress.get()[c] << " ";
            std::cout << std::hex << hash.sha512_ptr(TMPa,TMPb).get()[i] << " ";
            if(i==7) {
                std::cout << "\n\n";
            }
        }
    }

    /* TEST walletAddress */
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> testMap;
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>>::iterator
    itMap = testMap.begin();
    testMap.insert(itMap, std::pair<std::shared_ptr<uint64_t>, 
                   std::vector<uint8_t*>>(walletAddress, snd));
    struct Wallet TestWallet{walletAddress, snd, testMap};
    
    delete[] snd[0];
    delete[] snd[1];
    return 0;
}
