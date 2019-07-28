#ifndef _CONFIG_H_
#define _CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif



/*
		when MCU restarts,
	we need wait for a while for USB reconnect,
	you may need to change delay function due to different system(Linux or Windows or...).
*/
#include <windows.h>
#define DELAY_S(s)    Sleep(s)



/*
	0:
		not compatible with versions below win10.
	1:
		compatible with versions below win10.
*/
#define IS_COMPATIBLE_WITH_VERSIONS_BELOW_WIN10    1



#define USB_COMMUNICATION_TX_DATA_LENGTH    (1 + 64)
#define USB_COMMUNICATION_RX_DATA_LENGTH    (64)

#define USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS    1000



#define TARGET_HID_DEVICE_VID     ((unsigned short)0x3412)
#define TARGET_HID_DEVICE_PID     ((unsigned short)0x7856)



/* host computer sends this string to try to enter bootloader code. */
#define BOOTLOADER_CODE_ENTER_COMMAND_STRING     "user application enter bootloader"



/*
		the bin file name of original firmware and released firmware is defined here,
	you can modify the two name if it is needed.
*/
#define ORIGINAL_FIRMWARE_BIN_FILE_NAME     "user_application_release_by_embeded_engineer.bin"

#define RELEASED_FIRMWARE_BIN_FILE_NAME     "user_application_release_by_platform_engineer.bin"



/*
		the bin file of original firmware has be encrypted,
	so it needs decryption key,
	KEY_FOR_PLATFORM is used by our platform engineers.
		the size must not larger than AES_KEYLEN bytes(include last '\0'),
	there are AES128 and AES192 and AES256,
	their AES_KEYLEN is different,
	which we are using can be found in aes.h.
		KEY_FOR_PLATFORM can be modified,
	but platform engineers should let embeded engineers know the change.
*/
#define KEY_FOR_PLATFORM    "KEYFORPLATFORM" /* our platform engineers SHOULD let nobody else know the key! */

/* the bin file structure of original firmware is defined below. */
#define ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_0    ((unsigned char)0xCC)
#define ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_1    ((unsigned char)0xDD)
#define ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_2    ((unsigned char)0xEE)
#define ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_3    ((unsigned char)0xFF)
typedef struct {
	unsigned char fixed_prefix_0;
	unsigned char fixed_prefix_1;
	unsigned char fixed_prefix_2;
	unsigned char fixed_prefix_3;

	unsigned short release_year;
	unsigned char  release_month;
	unsigned char  release_day;
	unsigned char  release_hour;
	unsigned char  release_minute;

	unsigned char version_major;
	unsigned char version_minor;
	unsigned char version_revision;

	unsigned char developer_name[3 + 16 + 8];

	/* int(4 bytes) but long(8 bytes in LinuxX64) */
	unsigned int firmware_length;
	unsigned int firmware_crc32;

	/* the encrypted firmware location is started from here. */
} ORIGINAL_FIRMWARE_BIN_FILE_HEADER;



#ifdef __cplusplus
}
#endif

#endif
