/// algoritm banal de steganografie - tehnica LSB pe imagini bitmap cu 24 biti per pixel, fara compresie

#include <iostream>
#include <fstream>

#define COMPRESED_ERR 0
#define BPP_ERR 1
#define HEIGHT_ERR 2
#define H_ERR 3
#define SIZE_ERR 4

#define MODPOW32(x) ((x) & 4294967295)

#define MOD32(x) ((x) & 31)
#define ROTL32(x, n) (((x << MOD32(n)) & 4294967295) | ((x >> (32 - MOD32(n))) & ((1 << MOD32(n)) - 1)))
#define ROTR32(x, n) ((x >> MOD32(n)) | ((x << (32 - MOD32(n))) & 4294967295))

#define MOD64(x) ((x) & 63)
#define ROTL64(x, n) (ulong)(((((ulong)x) << MOD64(n)) & 18446744073709551615) | ((ulong)(x >> (64 - MOD64(n))) & ((1LL << MOD64(n)) - 1)))
#define ROTR64(x, n) (ulong)((ulong)(x >> MOD64(n)) | ((((ulong)x) << (64 - MOD64(n))) & 18446744073709551615))

#define P64 (ulong)0xb7e151628aed2a6b
#define Q64 (ulong)0x9e3779b97f4a7c15

#define W_BYTE_SIZE 8
#define KEY_BYTE_SIZE 128
#define ROUNDS 18
#define EXPANDED_KEY_W_SIZE 2 * (ROUNDS + 1)

typedef unsigned int uint;
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned long long ulong;

ulong * EXPANDED_KEY;
byte * KEY;

uint touint(byte * buf){

    uint val = 0;
    val |= buf[3];
    val <<= 8;
    val |= buf[2];
    val <<= 8;
    val |= buf[1];
    val <<= 8;
    val |= buf[0];

    return val;
}

int toint(byte * buf){

    int val = 0;
    val |= buf[3];
    val <<= 8;
    val |= buf[2];
    val <<= 8;
    val |= buf[1];
    val <<= 8;
    val |= buf[0];

    return val;
}

ushort toushort(byte * buf){

    ushort val = 0;
    val |= buf[1];
    val <<= 8;
    val |= buf[0];

    return val;
}

byte * readfile(char * path){

    std::ifstream org_image(path, std::ios::binary);

    byte * header = new byte[54];
    org_image.read((char *)header, 54);

    uint filesize = touint(header + 2);

    int pixel_height = toint(header + 0x16);
    if(pixel_height < 0)
        pixel_height *= -1;

    ushort bpp = toushort(header + 0x1c);
    uint compression = touint(header + 0x1e);

    /// verific daca se indeplinesc conditiile

    if(header[0] != 0x42 || header[1] != 0x4d)
        throw(H_ERR);
    else if(compression != 0)
        throw(COMPRESED_ERR);
    else if(bpp != 24)
        throw(BPP_ERR);
    else if(pixel_height < 2)
        throw(HEIGHT_ERR);

    org_image.seekg(0);

    byte * allfile = new byte[filesize];
    org_image.read((char *)allfile, filesize);

    delete[] header;

    org_image.close();

    return allfile;
}

void setbit(byte * to_alter, uint bit_pos, uint & from){

    to_alter[0] = ((to_alter[0] >> 1) << 1) | ((from >> bit_pos) & 1);
}

void setbit(byte * to_alter, uint bit_pos, byte * from){

    uint offset = bit_pos / 8;
    bit_pos %= 8;

    to_alter[0] = ((to_alter[0] >> 1) << 1) | ((from[offset] >> bit_pos) & 1);
}

void insert_message(byte * content, byte * msg, uint msg_size){

    uint imgoffset = touint(content + 0xa);

    int pixel_width = toint(content + 0x12);
    int pixel_height = toint(content + 0x16);

    if(pixel_height < 0)
        pixel_height *= -1;

    uint row_byte_length = 3 * pixel_width / 4;

    uint byte_padding_size = 4 - 3 * pixel_width % 4;
    if(byte_padding_size == 4)
        byte_padding_size = 0;

    row_byte_length += byte_padding_size;

    //const uint IMG_BYTE_SIZE = row_byte_length * pixel_height;

    if((row_byte_length - byte_padding_size) * pixel_height < 32 + msg_size * 8)
        throw(SIZE_ERR);

    byte * img = content + imgoffset;

    uint msg_bit_count = 0; /// pentru a avansa prin bitii de ascuns

    /// voi rezerva primii 32 biti pentru a insera lungimea mesajului in octeti
    /// dupa care pentru fiecare byte din imagine, ultimul bit va contine informatie ascunsa
    /// daca am mai multi octeti in imagine decat am nevoie, ii las neatinsi

    for(uint row = 0; row < pixel_height && msg_bit_count < msg_size * 8 + 32; row++)
        for(uint b = 0; b < row_byte_length - byte_padding_size && msg_bit_count < msg_size * 8 + 32; b++){

            if(msg_bit_count < 32)
                setbit(img + row * row_byte_length + b, msg_bit_count, msg_size);
            else
                setbit(img + row * row_byte_length + b, msg_bit_count - 32, msg);

            msg_bit_count += 1;
        }
}

void getbit(uint & to_alter, uint bit_pos, byte * from){

    if((from[0] & 1) == 0){

        to_alter = (to_alter & ((1 << bit_pos) - 1)) | ((to_alter >> (bit_pos + 1)) << (bit_pos + 1));
    }
    else{

        to_alter = (to_alter & ((1 << bit_pos) - 1)) | (((to_alter >> bit_pos) | 1) << bit_pos);
    }
}

void getbit(byte * to_alter, uint bit_pos, byte * from){

    uint offset = bit_pos / 8;
    bit_pos %= 8;

    if((from[0] & 1) == 0){

        to_alter[offset] = (to_alter[offset] & ((1 << bit_pos) - 1)) | ((to_alter[offset] >> (bit_pos + 1)) << (bit_pos + 1));
    }
    else{

        to_alter[offset] = (to_alter[offset] & ((1 << bit_pos) - 1)) | (((to_alter[offset] >> bit_pos) | 1) << bit_pos);
    }
}

byte * extract_message(byte * content, uint & msg_size){

    uint imgoffset = touint(content + 0xa);

    int pixel_width = toint(content + 0x12);
    int pixel_height = toint(content + 0x16);

    if(pixel_height < 0)
        pixel_height *= -1;

    uint row_byte_length = 3 * pixel_width / 4;

    uint byte_padding_size = 4 - 3 * pixel_width % 4;
    if(byte_padding_size == 4)
        byte_padding_size = 0;

    row_byte_length += byte_padding_size;

    const uint IMG_BYTE_SIZE = row_byte_length * pixel_height;

    byte * img = content + imgoffset;

    uint msg_bit_count = 0; /// pentru a avansa prin bitii ascunsi

    byte * msg;

    msg_size = 0;

    for(uint row = 0; row < pixel_height && msg_bit_count < msg_size * 8 + 32; row++)
        for(uint b = 0; b < row_byte_length - byte_padding_size && msg_bit_count < msg_size * 8 + 32; b++){

            if(msg_bit_count == 32)
                msg = new byte[msg_size];

            if(msg_bit_count < 32)
                getbit(msg_size, msg_bit_count, img + row * row_byte_length + b);
            else
                getbit(msg, msg_bit_count - 32, img + row * row_byte_length + b);

            msg_bit_count += 1;
        }

    return msg;
}

ulong * RC5_key_expander(byte * key){

    size_t org_key_w_size = KEY_BYTE_SIZE / W_BYTE_SIZE;

    ulong * org_key = new ulong[org_key_w_size];

    for(uint i = 0; i < org_key_w_size; i++)
        org_key[i] = 0;

    for(uint i = 0; i < KEY_BYTE_SIZE; i++){

        org_key[i / W_BYTE_SIZE] = (org_key[i / W_BYTE_SIZE] << 8) | key[i];
    }

    ulong * expanded_key = new ulong[EXPANDED_KEY_W_SIZE];

    expanded_key[0] = P64;

    for(int i = 1; i < EXPANDED_KEY_W_SIZE; i++)
        expanded_key[i] = expanded_key[i - 1] + Q64;

    ulong a = 0;
    ulong b = 0;
    int i = 0;
    int j = 0;

    size_t mix_rounds;

    if(EXPANDED_KEY_W_SIZE > org_key_w_size)
        mix_rounds = 3 * EXPANDED_KEY_W_SIZE;
    else
        mix_rounds = 3 * org_key_w_size;

    for(uint cnt = 0; cnt < mix_rounds; cnt++){

        expanded_key[i] = ROTL64((expanded_key[i] + a + b), 3);
        a = expanded_key[i];


        org_key[j] = ROTL64((org_key[j] + a + b), a + b);
        b = org_key[j];

        i += 1;
        i %= EXPANDED_KEY_W_SIZE;

        j += 1;
        j %= org_key_w_size;

    }

    /// pentru a suprascrie acel spatiu din memorie
    for(uint i = 0; i < org_key_w_size; i++)
        org_key[i] = 18446744073709551615;

    delete[] org_key;

    return expanded_key;
}

void RC5_block_encryptor(byte * to_encrypt, byte * buffer_for_ciphertext, ulong * expanded_key = EXPANDED_KEY){

    ulong first_word = 0;
    ulong second_word = 0;

    for(int i = 0; i < 8; i++){

        first_word = (first_word << 8) | to_encrypt[i];
        second_word = (second_word << 8) | to_encrypt[i + 8];
    }

    first_word = first_word + expanded_key[0];
    second_word = second_word + expanded_key[1];

    for(int r = 1; r < ROUNDS; r++){

        first_word = ROTL64((first_word ^ second_word), second_word) + expanded_key[2 * r];
        second_word = ROTL64((first_word ^ second_word), first_word) + expanded_key[2 * r + 1];
    }

    for(int i = 7; i >= 0; i--){

        buffer_for_ciphertext[i] = first_word & 255;
        first_word >>= 8;
    }

    for(int i = 15; i >= 8; i--){

        buffer_for_ciphertext[i] = second_word & 255;
        second_word >>= 8;
    }
}

void RC5_block_decryptor(byte * to_decrypt, byte * buffer_for_message, ulong * expanded_key = EXPANDED_KEY){

    ulong first_word = 0;
    ulong second_word = 0;

    for(int i = 0; i < 8; i++){

        first_word = (first_word << 8) | to_decrypt[i];
        second_word = (second_word << 8) | to_decrypt[i + 8];
    }

    for(int r = ROUNDS - 1; r > 0; r--){

        second_word = ROTR64((second_word - expanded_key[2 * r + 1]), first_word) ^ first_word;
        first_word = ROTR64((first_word - expanded_key[2 * r]), second_word) ^ second_word;
    }

    second_word = second_word - expanded_key[1];
    first_word = first_word - expanded_key[0];

    for(int i = 7; i >= 0; i--){

        buffer_for_message[i] = first_word & 255;
        first_word >>= 8;
    }

    for(int i = 15; i >= 8; i--){

        buffer_for_message[i] = second_word & 255;
        second_word >>= 8;
    }
}

byte * RC5_CBC_encryption(byte * to_encrypt, size_t to_encrypt_size, size_t & stolen_length, ulong * expanded_key = EXPANDED_KEY){

    /// voi folosi vector de initializare explicit (primul bloc va fi random tot timpul)
    /// voi folosi de asemenea cipher stealing

    size_t padding_size;

    if(to_encrypt_size % (2 * W_BYTE_SIZE))
        padding_size = (2 * W_BYTE_SIZE) - (to_encrypt_size % (2 * W_BYTE_SIZE));
    else
        padding_size = 0;

    size_t to_encrypt_padded_size = to_encrypt_size + padding_size;

    to_encrypt_padded_size += (2 * W_BYTE_SIZE); /// pentru blocul random de la inceput

    size_t to_encrypt_block_cnt = to_encrypt_padded_size / (2 * W_BYTE_SIZE);

    /// voi crea explicit numai primul bloc, si ultimul bloc daca este nevoie
    /// pentru a nu mai copia tot continutul de criptat intr un nou buffer
    /// doar pentru un eventual padding la final si pentru blocul random de inceput

    byte * first_noise_block = new byte[2 * W_BYTE_SIZE];

    byte * last_padded_block;
    if(padding_size)
        last_padded_block = new byte[2 * W_BYTE_SIZE];

    /// initializare bloc random
    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
        first_noise_block[i] = rand() % 256;

    /// iv
    byte * iv = new byte[2 * W_BYTE_SIZE];
    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
        iv[i] = rand() % 256;

    /// ultimul bloc cu padding
    if(padding_size){

        uint incomplete_block_index = (to_encrypt_size / (2 * W_BYTE_SIZE)) * 2 * W_BYTE_SIZE;

        for(uint i = 0; i < (2 * W_BYTE_SIZE) - padding_size; i++)
            last_padded_block[i] = to_encrypt[incomplete_block_index + i];

        for(uint i = (2 * W_BYTE_SIZE) - padding_size; i < 2 * W_BYTE_SIZE; i++)
            last_padded_block[i] = 0;
    }

    /// buffer ul unde RC5_block_encryptor adauga pe rand blocurile criptate
    byte * encrypted_message = new byte[to_encrypt_padded_size];

    /// criptarea primului bloc

    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
        first_noise_block[i] ^= iv[i];

    /// va pune in primele 2 * W_BYTE_SIZE pozitii ale buffer ului encrypted_message blocul criptat
    RC5_block_encryptor(first_noise_block, encrypted_message, expanded_key);

    /// sterg memoria alocata pentru iv ul initial si reactualizez pointerul catre alta adresa
    /// pentru a nu trebui sa tot copiez in iv valorile necesare
    delete[] iv;

    /// actualizarea iv-ului
    iv = encrypted_message;

    /// criptarea urmatoarelor blocuri cu exceptia ultimului
    for(uint block = 1; block < to_encrypt_block_cnt - 1; block++){

        uint to_encrypt_base_pos = (block - 1) * 2 * W_BYTE_SIZE;

        /// XOR cu iv ul curent
        for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
            to_encrypt[to_encrypt_base_pos + i] ^= iv[i];

        /// criptare, cu pozitiile buffer elor corespunzatoare
        RC5_block_encryptor(to_encrypt + to_encrypt_base_pos, encrypted_message + block * 2 * W_BYTE_SIZE, expanded_key);

        /// reactualizare iv
        iv = encrypted_message + block * 2 * W_BYTE_SIZE;
    }

    /// criptarea ultimului bloc
    if(padding_size){

        /// XOR cu iv ul curent
        for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
            last_padded_block[i] ^= iv[i];

        /// criptare, cu pozitiile buffer elor corespunzatoare
        RC5_block_encryptor(last_padded_block, encrypted_message + (to_encrypt_block_cnt - 1) * 2 * W_BYTE_SIZE, expanded_key);

        /// nu mai reinitialize iv deoarece sunt la ultimul pas al criptarii
    }
    else{

        /// criptez exact ca in for ul de mai sus

        uint to_encrypt_base_pos = (to_encrypt_block_cnt - 1 - 1) * 2 * W_BYTE_SIZE;

        /// XOR are cu iv ul curent
        for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
            to_encrypt[to_encrypt_base_pos + i] ^= iv[i];

        /// criptare, cu pozitiile buffer elor corespunzatoare
        RC5_block_encryptor(to_encrypt + to_encrypt_base_pos, encrypted_message + (to_encrypt_block_cnt - 1) * 2 * W_BYTE_SIZE, expanded_key);

        /// nu mai reinitialize iv deoarece sunt la ultimul pas al criptarii
    }

    /// eliminarea bucatii furate

    if(padding_size){

        uint base_pos = (to_encrypt_block_cnt - 2) * 2 * W_BYTE_SIZE;

        for(uint i = 2 * W_BYTE_SIZE - padding_size; i < 2 * W_BYTE_SIZE; i++)
            encrypted_message[base_pos + i] = 0;
    }

    /// inversarea ultimelor doua cipher block uri

    uint base_pos = (to_encrypt_block_cnt - 2) * 2 * W_BYTE_SIZE;

    byte swap_block;
    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++){

        swap_block = encrypted_message[base_pos + i];
        encrypted_message[base_pos + i] = encrypted_message[base_pos + i + 2 * W_BYTE_SIZE];
        encrypted_message[base_pos + i + 2 * W_BYTE_SIZE] = swap_block;
    }

    stolen_length = padding_size;

    /// !!! STERG BUFFER UL INITIAL AL MESAJULUI DE CRIPTAT !!!
    delete[] to_encrypt;

    return encrypted_message;
}

byte * RC5_CBC_decryption(byte * to_decrypt, size_t to_decrypt_size, size_t stolen_length, ulong * expanded_key = EXPANDED_KEY){

    /// to_decrypt_size contine dimensiunea to_decrypt cu tot cu 0 uri in locul bucatii furate
    /// acest lucru va fi asigurat inainte de apelarea functiei

    size_t to_decrypt_block_cnt = to_decrypt_size / (2 * W_BYTE_SIZE);

    /// reinversarea penultimului bloc cu ultimul

    uint base_pos = (to_decrypt_block_cnt - 2) * 2 * W_BYTE_SIZE;

    byte swap_block;
    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++){

        swap_block = to_decrypt[base_pos + i];
        to_decrypt[base_pos + i] = to_decrypt[base_pos + i + 2 * W_BYTE_SIZE];
        to_decrypt[base_pos + i + 2 * W_BYTE_SIZE] = swap_block;
    }

    /// recreerea bucatii prin decriptarea ultimului bloc

    byte * last_decrypted = new byte[2 * W_BYTE_SIZE];

    base_pos = (to_decrypt_block_cnt - 1) * 2 * W_BYTE_SIZE;

    RC5_block_decryptor(to_decrypt + base_pos, last_decrypted, expanded_key);

    base_pos = (to_decrypt_block_cnt - 2) * 2 * W_BYTE_SIZE;

    for(uint i = 2 * W_BYTE_SIZE - stolen_length; i < 2 * W_BYTE_SIZE; i++)
        to_decrypt[base_pos + i] = last_decrypted[i];

    /// decriptare propriu zisa

    /// initializez iv direct cu primul ciphertext
    /// voi reactualiza iv ul cu pozitiile corespunzatoare din to_decrypt la fiecare pas
    byte * iv = to_decrypt;

    /// nu voi retine primul bloc de noise decriptat si nici padding ul cu 0 din ultimul bloc
    byte * decrypted_message = new byte[to_decrypt_size - 2 * W_BYTE_SIZE - stolen_length];

    for(uint block = 1; block < to_decrypt_block_cnt - 1; block++){

        RC5_block_decryptor(to_decrypt + block * 2 * W_BYTE_SIZE, decrypted_message + (block - 1) * 2 * W_BYTE_SIZE, expanded_key);

        for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
            decrypted_message[(block - 1) * 2 * W_BYTE_SIZE + i] ^= iv[i];

        iv = to_decrypt + block * 2 * W_BYTE_SIZE;
    }

    /// eliminarea padding ului cu 0 din ultimul bloc

    base_pos = (to_decrypt_block_cnt - 1 - 1) * 2 * W_BYTE_SIZE;

    for(uint i = 0; i < 2 * W_BYTE_SIZE; i++)
        last_decrypted[i] ^= iv[i];

    for(uint i = 0; i < 2 * W_BYTE_SIZE - stolen_length; i++)
        decrypted_message[base_pos + i] = last_decrypted[i];

    delete[] last_decrypted;

    delete[] to_decrypt;

    return decrypted_message;
}

void hide_message(char * img_path, char * message_path, char * vessel_path, ulong * encryption_key = EXPANDED_KEY){

    try{

        byte * vessel_image = readfile(img_path);

        std::ifstream plain_msg_file(message_path, std::ios::binary | std::ios::ate);

        uint plain_msg_size = plain_msg_file.tellg();

        byte * plain_msg = new byte[plain_msg_size];

        plain_msg_file.seekg(0);
        plain_msg_file.read((char *)plain_msg, plain_msg_size);

        plain_msg_file.close();

        size_t stolen_length = 0;

        byte * encrypted_message = RC5_CBC_encryption(plain_msg, plain_msg_size, stolen_length, encryption_key);

        uint encrypted_length = plain_msg_size + 2 * W_BYTE_SIZE + stolen_length;

        /// concatenez mesajul criptat cu stolen_length
        uint to_hide_length = encrypted_length + sizeof(stolen_length);
        byte * to_hide = new byte[to_hide_length];

        for(uint i = 0; i < encrypted_length; i++)
            to_hide[i] = encrypted_message[i];

        for(uint i = encrypted_length; i < to_hide_length; i++){

            to_hide[i] = stolen_length & 255;
            stolen_length >>= 8;
        }

        insert_message(vessel_image, to_hide, to_hide_length);

        std::ofstream imgfile(vessel_path, std::ios::binary | std::ios::trunc);

        imgfile.write((char *)vessel_image, touint(vessel_image + 2));
        imgfile.close();

        delete[] encrypted_message;
        delete[] to_hide;
    }
    catch(int errcode){

        if(errcode < 4){
            std::cout << "Imaginea cărăuș aleasă nu are proprietățile necesare!";
        }
        else{
            std::cout << "Imaginea cărăuș aleasă nu este suficient de mare!";
        }
        return;
    }
}

void uncover_message(char * vessel_path, char * uncovered_path, ulong * encryption_key = EXPANDED_KEY){

    try{

        byte * vessel_image = readfile(vessel_path);

        uint hidden_size = 0;

        byte * hidden_bytes = extract_message(vessel_image, hidden_size);

        size_t stolen_length = 0;

        for(uint i = 0; i < 8; i++){

            stolen_length <<= 8;
            stolen_length |= hidden_bytes[hidden_size - i - 1];
        }

        uint encrypted_size = hidden_size - sizeof(stolen_length);

        byte * decrypted_content = RC5_CBC_decryption(hidden_bytes, encrypted_size, stolen_length, encryption_key);

        uint uncovered_size = encrypted_size - 16 - stolen_length;

        std::ofstream uncovered_file(uncovered_path, std::ios::binary | std::ios::trunc);

        uncovered_file.write((char *)decrypted_content, uncovered_size);

        uncovered_file.close();

        delete[] decrypted_content;
        delete[] vessel_image;
    }
    catch(int errcode){

        if(errcode < 4){
            std::cout << "Imaginea cărăuș aleasă nu are proprietățile necesare!";
        }
        return;
    }
}

void KEY_INIT(char * keypath){

    std::ifstream keyfile(keypath, std::ios::binary);

    KEY = new byte[KEY_BYTE_SIZE];

    keyfile.read((char *)KEY, KEY_BYTE_SIZE);

    EXPANDED_KEY = RC5_key_expander(KEY);

    keyfile.close();
}

void TEST_DATA(){

    /// RANDOM TEST LINES

    /*byte * vessel_image = readfile("orgimg.bmp");

    std::ifstream plain_msg_file("msgfile.txt", std::ios::binary | std::ios::ate);

    uint plain_msg_size = plain_msg_file.tellg();

    byte * plain_msg = new byte[plain_msg_size];

    plain_msg_file.seekg(0);
    plain_msg_file.read((char *)plain_msg, plain_msg_size);

    plain_msg_file.close();

    insert_message(vessel_image, plain_msg, plain_msg_size);

    std::ofstream imgfile("orgimg2.bmp", std::ios::binary | std::ios::trunc);

    imgfile.write((char *)vessel_image, touint(vessel_image + 2));
    imgfile.close();

    vessel_image = readfile("orgimg2.bmp");

    uint s = 0;
    byte * extr = extract_message(vessel_image, s);

    for(int i = 0; i < s; i++)
        std::cout << extr[i];*/
}

int main(){

    /* TEST DATA FOR ALGORITHM */

    KEY_INIT("keyfile.txt");

    hide_message("orgimg.bmp", "msgfile.txt", "vessel_img.bmp");

    //uncover_message("vessel_img.bmp", "extracted.txt");

    return 0;
}
