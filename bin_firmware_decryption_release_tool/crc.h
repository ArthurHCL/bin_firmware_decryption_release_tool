#ifndef _CRC_H_
#define _CRC_H_

#ifdef __cplusplus
extern "C" {
#endif



unsigned int crc32(const unsigned char * const s, const unsigned int len);

void crc32_batch_prepare(unsigned int * const crc32val);
void crc32_batch_calculating(const unsigned char * const s, const unsigned int len, unsigned int * const crc32val);
void crc32_batch_finish(unsigned int * const crc32val);



#ifdef __cplusplus
}
#endif

#endif
