/*
 * sgo_fast.c - hot loops for the FRF/SGO decoder.
 *
 * Compiled to sgo_fast.dll and called through ctypes (sgo_fast.py). The Python
 * implementations remain as a fallback, so a missing DLL only costs speed.
 *
 *   sgo_dsg_decrypt(key256, in, out, n)
 *   sgo_lzss10(in, inlen, out, outlen)  -> bytes produced, or -1 on bad stream
 *   sgo_lzz22 (in, inlen, out, outlen)  -> bytes produced, or -1 on bad stream
 *   sgo_table_decrypt(table, in, out, n)   SGO format-1 PQ cipher
 *   sgo_feedback(table, in, out, n)        early 02EA feedback cipher
 */
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT void sgo_dsg_decrypt(const uint8_t *key, const uint8_t *in,
                            uint8_t *out, size_t length)
{
    unsigned offset = 0, rolling = 0, last = 0;
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned plain = key[(in[i] + offset) & 0xFF];
        offset = (offset + plain + last) & 0xFF;
        rolling += 0x167;
        offset = (offset + key[(rolling >> 8) & 0xFF]) & 0xFF;
        last = plain;
        out[i] = (uint8_t)plain;
    }
}

EXPORT long sgo_lzss10(const uint8_t *in, size_t in_length,
                       uint8_t *out, size_t out_length)
{
    size_t pos = 0, produced = 0;
    while (produced < out_length) {
        unsigned flags, bit;
        if (pos >= in_length) {
            return -1;
        }
        flags = in[pos++];
        for (bit = 7; bit < 8 && produced < out_length; bit--) {
            if (!((flags >> bit) & 1)) {
                if (pos >= in_length) {
                    return -1;
                }
                out[produced++] = in[pos++];
            } else {
                unsigned word, count, disp, k;
                if (pos + 2 > in_length) {
                    return -1;
                }
                word = ((unsigned)in[pos] << 8) | in[pos + 1];
                pos += 2;
                count = word >> 10;
                disp = word & 0x3FF;
                if (disp == 0 || disp > produced) {
                    return -1;
                }
                if (count > out_length - produced) {
                    count = (unsigned)(out_length - produced);
                }
                for (k = 0; k < count; k++) {
                    out[produced] = out[produced - disp];
                    produced++;
                }
            }
        }
    }
    return (long)produced;
}

EXPORT long sgo_lzz22(const uint8_t *in, size_t in_length,
                      uint8_t *out, size_t out_length)
{
    size_t pos = 0, produced = 0;
    while (produced < out_length && pos < in_length) {
        unsigned flags, bit;
        flags = in[pos++];
        for (bit = 7; bit < 8 && produced < out_length; bit--) {
            if (!((flags >> bit) & 1)) {
                if (pos >= in_length) {
                    return -1;
                }
                out[produced++] = in[pos++];
            } else {
                unsigned word, count, disp, k;
                if (pos + 2 > in_length) {
                    return -1;
                }
                word = ((unsigned)in[pos] << 8) | in[pos + 1];
                pos += 2;
                count = word >> 11;
                disp = word & 0x7FF;
                if (disp == 0 || disp > produced) {
                    return -1;
                }
                if (count > out_length - produced) {
                    count = (unsigned)(out_length - produced);
                }
                for (k = 0; k < count; k++) {
                    out[produced] = out[produced - disp];
                    produced++;
                }
            }
        }
    }
    return (long)produced;
}

/* SGO format-1 PQ cipher: table permutation plus a rolling 0x167 counter and
   the container XOR-FF layer, state starting at zero per block. */
EXPORT void sgo_table_decrypt(const uint8_t *table, const uint8_t *in,
                              uint8_t *out, size_t length)
{
    unsigned offset = 0, rolling = 0, last = 0;
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned plain = table[((in[i] ^ 0xFF) + offset) & 0xFF];
        rolling = (rolling + 0x167) & 0xFFFF;
        offset = (offset + plain + last + table[(rolling >> 8) & 0xFF]) & 0xFF;
        last = plain;
        out[i] = (uint8_t)plain;
    }
}

/* Early 02EA cipher: plaintext is table[(stored + previous stored) & 0xFF],
   with 0xFF as the previous byte at the start of every block. */
EXPORT void sgo_feedback(const uint8_t *table, const uint8_t *in,
                         uint8_t *out, size_t length)
{
    unsigned previous = 0xFF;
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned stored = in[i];
        out[i] = table[(stored + previous) & 0xFF];
        previous = stored;
    }
}
