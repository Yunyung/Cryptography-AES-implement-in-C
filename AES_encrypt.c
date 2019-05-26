/**
 * AES Encryption Sysytem 
 * The chinese is encoded by UTF-8
 * Implment AES-128, AES-192, AES-256
 * 
 * 
 * The Encrpytion and decryption on 'char' 
 * Ex: AES-128
 * plaintext: 'abcdefghijklmnop'
 * key: 'abcdefghijklmnop'
 * 
 * Both English and chinese are commented in program
 */

#include <stdio.h>
/** plaintext or ciphertext 32bit block number (4, 128bits) , 1 block is diveded to 4 subblock
 *  Each sublock is 8 bit = 1 character
 *  AES中，規範只允許 128bits 輸入，每個 block 定義為代表 column (一列4個小區塊，每區塊8bits)
 *  固定義 Number of block(Nb = 4) (4 * block size = 128)
 */
#define Nb 4 

int Nr = 0; /* Number of round(Nr), 加密運算執行回合數, AES-128(10r), AES-192(12), AES-256(14)*/
int Nb_k = 0;  /* Number of block of key, 鑰匙(每block-32bits)的block數量 AES-128(4 block), AES-192(6), AES-256(8) */

unsigned char in[16];          // plaintext block input array, 明文區塊輸入char陣列
unsigned char out[16];         // ciphertext block output array, 密文區塊輸出陣列
unsigned char state[4][4];     // temp state array in encrypt state, 加密運算過程中的的狀態陣列 4 * 4 
unsigned char Roundkey[240];   // round key array, stored Main Key and Expanded Key (Ex: AES-128(44words/176 bytes), AES-256(60w/260bytes)), 儲存主要鑰匙跟擴充鑰匙的陣列, w0(index 0 ~ 3) w1(index 4 ~ 7)....
unsigned char Key[32];         // Main key(input key Ex. AES-128(18 char), AES-256(32 char)), 輸入的金鑰


/* S-box */
int S_Box[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};


/**
 * Rcon used in KeyExpansion
 * Table gernerate from GF(2^8) 
 * Rcon[0] will not be used(Easy to code), set any redundant num
 * AES uses up to rcon[10] for AES-128 (as 11 round keys are needed), up to rcon[8] for AES-192, and up to rcon[7] for AES-256.
 */
int Rcon[11] = 
{
//   0     1     2     3      4    5     6     7     8    9     10
    0x87, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


/** Key Expansion function, 擴充鑰匙函數產生所有鑰匙
 *  Input: Key[](主鑰匙), Nr(round), Nb, Nb_k(AES-128(4 block), AES-192(6), AES-256(8))
 *  Output: Roundkey[], 產生所有子鑰匙 - AES-128(44), 192(52), 256(60), 
 */
void KeyExpansion(){
    unsigned char tempByte[4]; // store 4 temp Byte(1 word) when generate subkey
    unsigned char a0;       // temp - store byte when execute RotWord function
    
    /**
     * First Round subKey = Main/Input Key, Divide to {Nb_k} block (each 32bits) [w0, w1, w2, w3]
     * each block divide to 4 subblock(8bit)
     * Ex: AES-128, Nb_k = 4, 4 block W0 ~ W3
     * Ex: AES-256, Nb_k = 8, 8 block W0 ~ W7
     * 
     * 第一回合子鑰匙 = 主鑰匙分成四個(Nb=4) 8 位元區塊 (W0=32 bits)
     * 第一回合需要 Nk 個鑰匙區塊, AES-128:Nk=4, W0 ~ W3 
     * 一個小block為8 bit = 1 character
     */
    for (int i = 0;i < Nb_k;i++){
        Roundkey[i * 4] = Key[i * 4];
        Roundkey[i *4 + 1] = Key[i * 4 + 1];
        Roundkey[i *4 + 2] = Key[i * 4 + 2];
        Roundkey[i *4 + 3] = Key[i * 4 + 3];
    }

    /**
     * Generate other subkey, 
     * 產生其他回合鑰匙: 
     * Ex: AES-128: i= 4 ~ 43, 共 11 個 4block(128bit), 需 44 個word (W0 ~ W43).
     * Ex: AES-256: i = 8 ~ 59, 共需要 15個 4block(128bit), 需60word(W0~ W59)
     * 每跑完一次產生一個block
     */
    for (int i = Nb_k;i < (Nb * (Nr + 1));i++)
    {
        for (int j = 0;j < 4;j++){ // 處理每個block(W)
            tempByte[j] = Roundkey[(i - 1) * 4 + j]; // 要新增一個block(Word)故取前一個的W值存入tempW
        }
        if (i % Nb_k == 0){
            /**
             * Ex: AES-128 when generate W4, will use W3 do SubWord(RotWord(tempW)) XOR Rcon[4/4]
             *     AES-128 i 是 4 的倍數的 Wi 用 Wi-1產生 Wi =  SubWord(RotWord(Wi-1)) XOR Rcon[i/4]
             */

            // RotWord function, [a0, a1, a2, a3](4byte) left circular shift in a word [a1, a2, a3, a0]
            a0 = tempByte[0];
            tempByte[0] = tempByte[1];
            tempByte[1] = tempByte[2];
            tempByte[2] = tempByte[3];
            tempByte[3] = a0;

            // SubWord function (S-Box substitution)
            tempByte[0] = S_Box[(int)tempByte[0]];
            tempByte[1] = S_Box[(int)tempByte[1]];
            tempByte[2] = S_Box[(int)tempByte[2]];
            tempByte[3] = S_Box[(int)tempByte[3]];
            
            // XOR Rcon[i/4], only leftmost byte are changed (只會XOR最左的byte)
            tempByte[0] = tempByte[0] ^ Rcon[i / Nb_k]; 
        }
        else if (Nb_k == 8 && i % Nb_k == 4){
            // Only AES-256 used, 僅 AES-256 使用此規則, 
            // 當 i mod 4 = 0 且 i mod 8 ≠ 0 時，Wn = SubWord (Wn−1) XOR Wn−8
            tempByte[0] = S_Box[(int)tempByte[0]];
            tempByte[1] = S_Box[(int)tempByte[1]];
            tempByte[2] = S_Box[(int)tempByte[2]];
            tempByte[3] = S_Box[(int)tempByte[3]];
        }
        /**
         * Wn = Wn-1 XOR Wk    k = current word - Nb_k
         * Ex: AES-128   Nb_k = 4  when W5 = Wn-1(W4) XOR Wk(W1)
         * Ex: AES-256   Nb_k = 8  when W10 = Wn-1(W9) XOR Wk(W2) 
         */
        Roundkey[i * 4 + 0] = Roundkey[(i - Nb_k) * 4 + 0] ^ tempByte[0];
        Roundkey[i * 4 + 1] = Roundkey[(i - Nb_k) * 4 + 1] ^ tempByte[1];
        Roundkey[i * 4 + 2] = Roundkey[(i - Nb_k) * 4 + 2] ^ tempByte[2];
        Roundkey[i * 4 + 3] = Roundkey[(i - Nb_k) * 4 + 3] ^ tempByte[3];   
    }
}


/**
 *  Cipher() AES encrypt function
 *  Input: in[16] plaintext block(128 bits), Nr (Number of round), Key[]
 *  output: out[16] cipher block(128 bits), 
 */

// AddRoundKey, 鑰匙XOR函數
void AddRoundKey(int round)
{
    /**
     * 根據round來使用key(每次用1個block = 16byte)
     * first key index = round * 16 bytes = round * Nb * 4;
     * Nb = 4
     */
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= Roundkey[(i * Nb + j) + (round * Nb * 4)]; 
}

// S-Box Substitution
void SubBytes(){
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = S_Box[state[i][j]];
}

// left Circular Shift (row), 列移位函數
void ShiftRows(){
    unsigned char tempByte;
    
    // 2nd row left Circular Shift 1 byte
    tempByte    = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tempByte;

    // 3th row left Circular Shift 2 byte
    tempByte    = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tempByte;

    tempByte    = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tempByte;

    // 4th row left Circular Shift 3 byte
    tempByte    = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = tempByte;
}

/**
 *  xtime macro: (input * {02}) mod {1b}  GF(2^8)
 *  02 = x = 00000010(binary) over GF(2^8)
 *  1b = x^8 + x^4 + x^3 + x^1 + 1 = 00011011(binary) over GF(2^8) 
 *  
 *  
 *  (x << 1) -- 代表 input * {02}  = shift 1 bit
 *  (x >> 7) -- input / 2^7, 代表只取第8個bit
 *  ((x >> 7) & 1) * 0x1b ----
 *  第 8 個 bit 若為 1 則代表 mod(2^7) 後會剩 => 00011011, 最後整個xtime(x)變成(x << 1) xor 00011011 (詳情請見GF(2^n)快速 mod運算的方式)
 *  第 8 個 bit 若為 0 會變成0 * 0x1b,                    最後整個xtime(x) (x << 1) XOR 0 = (x << 1)
 */
#define xtime(x)   ((x << 1) ^ (((x >> 7) & 0x01) * 0x1b))

/** 
 *  MixColumns() 混合行運算函數 
 *  執行4次(4 subblock) 每次的column執行如下
 *  c0     [2 3 1 1   [b0  
 *  c1      1 2 3 1    b1
 *  c2  =   1 1 2 3    b2
 *  c3      3 1 1 2]   b3]
 * 
 * 此為一線性轉換(linear transform)
 */
void MixColumns()
{
    unsigned char Tmp,Tm,t;
    for(int i = 0;i < 4;i++)
    {    
        t   = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        Tm  = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp ;
        Tm  = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp ;
        Tm  = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp ;
        Tm  = state[3][i] ^ t;           Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp ;
    }
}

void Cipher()
{
    int round = 0;
    
    /**
     *  將in[](plaintext) 轉換成 column 排列方式
     *  圖示:
     *  [b0 b1 ... b15] -> [b0 b4 b8  b12
     *                      b1 b5 b9  b13
     *                      b2 b6 b10 b14
     *                      b3 b7 b11 b15]
     */
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = in[i * 4 + j]; // transform input(plaintext), 將plaintext 轉成 column形式(w0, w1, w2, w3)
    

    // round 0 : add round key, 第0回合: 僅執行-key XOR block - key使用[w0 ~ w3]
    AddRoundKey(0);

    // Round 1 ~ Nr-1, 反覆執行 1 ~ Nr-1回合
    for (round = 1;round < Nr;round++){
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);

    /**
     *  將state[] transform 到 out[]上
     *  圖示:
     *   [c0 c4 c8  c12
     *    c1 c5 c9  c13    --> [c0 c1 c2 ... c15]
     *    c2 c6 c10 c14
     *    c3 c7 c11 c15]
     */
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            out[i * 4 + j]=state[j][i];
        
    
}


int main(){
    FILE *fp, *wp; // input file pointer, output(writer) file pointer
    int KeySize = 0; // key Size
    int feof_flag = 0; // detect end of file flag
    unsigned char input_key[32]; // user input Main Key, AES主Key
    unsigned char plaintext_block[16]; // plaintext, encrpty each block (128bit) once

    char fileName[50];

    printf("*** AES encryption System ***\n");
    while (KeySize != 128 && KeySize != 192 && KeySize != 256){
        printf("Enter AES key size (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize);
    }

    Nb_k = KeySize / 32;     // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr   = Nb_k + 6;         // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)

    if (KeySize == 128){
        printf("Enter AES KEY (16 characters) : ");
        scanf("%s", input_key);
        for (int i = 0;i < 16;i++)
            Key[i] = input_key[i];
    }
    else if (KeySize == 192){
        printf("Enter AES KEY (24 characters) : ");
        scanf("%s", input_key);
        for (int i = 0;i < 24;i++)
            Key[i] = input_key[i];
    }
    else if (KeySize == 256){
        printf("Enter AES KEY (32 characters) : ");
        scanf("%s", input_key);
        for (int i = 0;i < 32;i++)
            Key[i] = input_key[i];
    }
    else{
        printf("Error input to KeySize, Exit Now!");
        return 0;
    }
    /* Key Expansion function, 擴充鑰匙函數產生所有鑰匙 */
    KeyExpansion(); // Expansion Key - AES-128(44words/176 bytes), AES-192(52w/208 bytes), AES-256(60w/260bytes)

    /* get input plaintext */
    printf("Enter plaintext file name => ");
    scanf("%s", &fileName);
    if ((fp = fopen(fileName, "rb")) == NULL){
        printf("Open file Erorr...\n");
        return(0);
    }

    /* get output Ciphertext */
    printf("Enter Ciphertext file name to write out cipher => "); 
    scanf("%s", &fileName); 
    wp = fopen(fileName,"wb");

    feof_flag = 1;
    while(feof_flag == 1){
        /**
         *  read file, read 16 char (1block, 128bit) 
         *  if last block not fill 128bit, add 0x00 to fill with last block
         */
        for (int c = 0;c < 16;c++){
            plaintext_block[c] = fgetc(fp);

            if (feof(fp)){
                for (int padding = c;padding < 16;padding++){
                    plaintext_block[padding] = 0x00;
                }
                feof_flag = 0;
            }
        }

        for (int c = 0;c < 16;c++){
            in[c] = plaintext_block[c];
        }

        /**
         * Call Encrypt  function, encrypt one block (128 bit) once
         * input: in[](plaintext), Key[](key)
         * output: out[](cipher) 
         */
        Cipher(); 

        /* Write Ciphertext to file, 密文輸出到檔案上 */
        for(int c = 0; c < 16;c++)  
            fprintf(wp, "%c", out[c]);
        
        printf("Cipher : %s", out);
        char c;
        if ((c = fgetc(fp)) == EOF){
            feof_flag = 0;
        }
        else{
            ungetc(c, fp); // if not read EOF, restore character
        }
    }

    fclose(fp);
    rewind(wp);
    fclose(wp);
    printf("Encryption process complete !! \n");
    
}