#include <emscripten.h>
#include <vector>
#include <string>
#include <algorithm>
#include <zlib.h>
#include <cstring>

extern "C" {

// Helper: Base64 decode
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

// Helper: Zlib decompress
std::vector<unsigned char> zlib_decompress(const std::vector<unsigned char>& data, int windowBits = 15) {
    std::vector<unsigned char> decompressed;
    if (data.empty()) return decompressed;

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = data.size();
    strm.next_in = (Bytef*)data.data();

    if (inflateInit2(&strm, windowBits) != Z_OK) return decompressed;

    unsigned char out[32768];
    do {
        strm.avail_out = sizeof(out);
        strm.next_out = out;
        int ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return decompressed;
        }
        int have = sizeof(out) - strm.avail_out;
        decompressed.insert(decompressed.end(), out, out + have);
        if (ret == Z_STREAM_END) break;
    } while (strm.avail_out == 0);

    inflateEnd(&strm);
    return decompressed;
}

// AndLua algo_decrypt_string
void algo_decrypt_string(unsigned char* b, int len) {
    if (len <= 0) return;
    int size_minus_1 = len;
    int x = size_minus_1;
    int v5 = b[0] ^ x;
    int v6 = x + v5;
    for (int i = 0; i < size_minus_1; i++) {
        int v8 = x % 255;
        x += v6;
        b[i] = b[i] ^ v8;
    }
}

// UTF-8 check
bool is_valid_utf8(const unsigned char* data, int len) {
    int i = 0;
    while (i < len) {
        if (data[i] <= 0x7F) {
            if (data[i] < 0x20 && data[i] != 0x09 && data[i] != 0x0A && data[i] != 0x0D) return false;
            i += 1;
        } else if ((data[i] & 0xE0) == 0xC0) {
            if (i + 1 >= len || (data[i+1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((data[i] & 0xF0) == 0xE0) {
            if (i + 2 >= len || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((data[i] & 0xF8) == 0xF0) {
            if (i + 3 >= len || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

// AndLua Stage 2
void stage2_bytecode_patch(std::vector<unsigned char>& data) {
    int length = data.size();
    int i = 0;
    if (length > 30 && data[0] == 0x1b && data[1] == 'L' && data[2] == 'u' && data[3] == 'a') {
        i = 30;
    }
    while (i < length) {
        if (data[i] == 0x04) {
            if (i + 1 < length) {
                int payload_len = (int)data[i + 1] - 1;
                if (payload_len > 0 && (i + 2 + payload_len) <= length) {
                    std::vector<unsigned char> payload(data.begin() + i + 2, data.begin() + i + 2 + payload_len);
                    algo_decrypt_string(payload.data(), payload.size());
                    if (is_valid_utf8(payload.data(), payload.size())) {
                        std::copy(payload.begin(), payload.end(), data.begin() + i + 2);
                        i += 2 + payload_len;
                        continue;
                    }
                }
            }
        }
        i++;
    }
}

// LuaAppX Pro logic
void inc_bytes_be(unsigned char* iv) {
    for (int i = 15; i >= 0; i--) {
        if (++iv[i] != 0) break;
    }
}

void fake_aes_ctr_decrypt(unsigned char* data, int len, const unsigned char* key, unsigned char* iv) {
    for (int i = 0; i < len; i += 16) {
        int chunk_len = (len - i < 16) ? (len - i) : 16;
        unsigned char keystream[16];
        for (int j = 0; j < 16; j++) keystream[j] = key[j] ^ iv[j];
        for (int j = 0; j < chunk_len; j++) data[i + j] ^= keystream[j];
        inc_bytes_be(iv);
    }
}

// Exported Functions
EMSCRIPTEN_KEEPALIVE
uint8_t* decrypt_andlua(uint8_t* input, int len, int* out_len) {
    if (len <= 0) return nullptr;

    // Stage 1
    std::string b64_in((char*)input, len);
    if (b64_in.length() > 0) b64_in[0] = 'H';

    std::vector<unsigned char> decoded = base64_decode(b64_in);
    if (decoded.empty()) return nullptr;

    unsigned char init = 0;
    for (size_t i = 0; i < decoded.size(); i++) {
        init ^= decoded[i];
        decoded[i] = init;
    }

    if (decoded.size() > 1) decoded[0] = 0x78;
    std::vector<unsigned char> decompressed = zlib_decompress(decoded);
    if (decompressed.empty()) return nullptr;

    decompressed[0] = 0x1b;

    // Stage 2
    stage2_bytecode_patch(decompressed);

    *out_len = decompressed.size();
    uint8_t* result = (uint8_t*)malloc(decompressed.size());
    std::copy(decompressed.begin(), decompressed.end(), result);
    return result;
}

EMSCRIPTEN_KEEPALIVE
uint8_t* decrypt_luaappx(uint8_t* input, int len, int* out_len) {
    if (len < 12) return nullptr;

    std::string b64_in((char*)input + 12, len - 12);
    std::vector<unsigned char> decoded = base64_decode(b64_in);
    if (decoded.size() < 64) return nullptr;

    unsigned char key2[16], iv2[16], key1[16], iv1[16];
    std::memcpy(key2, decoded.data(), 16);
    std::memcpy(iv2, decoded.data() + 16, 16);
    std::memcpy(key1, decoded.data() + 32, 16);
    std::memcpy(iv1, decoded.data() + 48, 16);

    std::vector<unsigned char> payload_enc(decoded.begin() + 64, decoded.end());
    std::vector<unsigned char> payload = zlib_decompress(payload_enc);
    if (payload.empty()) {
        payload = zlib_decompress(payload_enc, -15); // Raw
    }
    if (payload.empty()) return nullptr;

    fake_aes_ctr_decrypt(payload.data(), payload.size(), key1, iv1);
    fake_aes_ctr_decrypt(payload.data(), payload.size(), key2, iv2);

    *out_len = payload.size();
    uint8_t* result = (uint8_t*)malloc(payload.size());
    std::copy(payload.begin(), payload.end(), result);
    return result;
}

EMSCRIPTEN_KEEPALIVE
void free_result(uint8_t* ptr) {
    free(ptr);
}

}
