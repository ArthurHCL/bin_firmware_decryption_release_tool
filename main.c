#include <stdbool.h>
#include <stdio.h>

#include "config.h"
#include "aes.h"
#include "hidapi.h"
#include "crc.h"



/*
		the code is a template to show how to resolve bin file of original firmware,
	and how to generate bin file of released firmware,
	which is going to be downloaded to MCU by USB communication.
		the code has not implement USB communication,
	so platform engineers need to add USB communication.
*/



/* device firmware update command list. */
typedef enum {
	DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY = 0x01,
	DFU_PACKET_INITIAL_PREPARE,
	DFU_PACKET_START_UPDATE,
	DFU_PACKET_UPDATING,
	DFU_PACKET_CHECK_CRC32,
	DFU_PACKET_ENABLE_APPLICATION_CODE
} DFU_PACKET_TYPE;

/* device firmware update command error code response. */
typedef enum {
	DFU_PACKET_ERROR_OK,

	DFU_PACKET_ERROR_OPERATION_SEQUENCE_CONFUSION,
	DFU_PACKET_ERROR_PERMISSION_KEY_FAIL,
	DFU_PACKET_ERROR_APPLICATION_CODE_SIZE_TOO_LARGE,
	DFU_PACKET_ERROR_APPLICATION_CODE_DISABLE_FAIL,
	DFU_PACKET_ERROR_FLASH_ERASE_FAIL,
	DFU_PACKET_ERROR_CONTINUOUS_FRAME_FAIL,
	DFU_PACKET_ERROR_FLASH_WRITE_FAIL,
	DFU_PACKET_ERROR_CRC32_CHECK_FAIL,
	DFU_PACKET_ERROR_SOFTDOG_STATUS_RESET_FAIL,
	DFU_PACKET_ERROR_APPLICATION_CODE_ENABLE_FAIL,
	DFU_PACKET_ERROR_DATA_LENGTH_IS_NOT_16_MULTIPLE,

	DFU_PACKET_ERROR_UNSUPPORTED_COMMAND = 255
} DFU_PACKET_ERROR_CODE;



static struct AES_ctx         AES_ctx_decrypted_for_platform;
static const unsigned char    key_for_platform[AES_KEYLEN] = KEY_FOR_PLATFORM;

static ORIGINAL_FIRMWARE_BIN_FILE_HEADER    original_firmware_bin_file_header;



static DFU_PACKET_ERROR_CODE    DFU_packet_error_code;

static unsigned int     original_permission_key;
static unsigned char    CRC32_repeat_time;
static unsigned int     calculated_permission_key;

static unsigned char    process_bar;



unsigned char Firmware_Update_Process_Bar_Get(void)
{
	return process_bar;
}

int main(void)
{
	const char    *original_firmware_bin_file_name;
	const char    *released_firmware_bin_file_name;
	FILE          *original_firmware_bin_file;
	FILE          *released_firmware_bin_file;
	size_t         read_items_amount;
	size_t         write_items_amount;
	bool           is_original_firmware_bin_file_read_complete = false;
	bool           is_released_firmware_bin_file_read_complete = false;
	unsigned char  data_buf[AES_BLOCKLEN];

	int                     i;
	int                     ret = 0;
	struct hid_device_info *target_hid_device_info;
	hid_device             *target_hid_device;
	unsigned short          target_HID_device_VID;
	unsigned short          target_HID_device_PID;
	int                     write_hid_data_amount;
	int                     read_hid_data_amount;
	unsigned char           hid_data_buf[USB_COMMUNICATION_TX_DATA_LENGTH];
	bool                    is_reconnect_needed = false;
	const char             *bootloader_code_enter_command_string;
	unsigned short          frame_number = 0;
	size_t                  read_items_amount_downloaded = 0;

	process_bar = 0;

	/* select bin firmware to be decrypted for release. */
	original_firmware_bin_file_name = ORIGINAL_FIRMWARE_BIN_FILE_NAME;
	released_firmware_bin_file_name = RELEASED_FIRMWARE_BIN_FILE_NAME;
	target_HID_device_VID = TARGET_HID_DEVICE_VID;
	target_HID_device_PID = TARGET_HID_DEVICE_PID;
	bootloader_code_enter_command_string = BOOTLOADER_CODE_ENTER_COMMAND_STRING;

	/* open bin file of original firmware. */
	original_firmware_bin_file = fopen(original_firmware_bin_file_name, "r");
	if (NULL == original_firmware_bin_file) {
		(void)printf("fopen() of original bin file: %s\n", original_firmware_bin_file_name);
		perror("    ");

		return -1;
	}

	//(void)printf("read file header start.\n");
	/* read bin file for file header. */
	read_items_amount = fread(&original_firmware_bin_file_header, 1, sizeof(ORIGINAL_FIRMWARE_BIN_FILE_HEADER), original_firmware_bin_file);
	if (sizeof(ORIGINAL_FIRMWARE_BIN_FILE_HEADER) != read_items_amount) {
		if (ferror(original_firmware_bin_file)) {
			perror("fread()");

			return -1;
		}

		if (feof(original_firmware_bin_file)) {
			clearerr(original_firmware_bin_file);

			(void)printf("%s has no content\n", original_firmware_bin_file_name);

			return -1;
		} else {
			(void)printf("fread() unknown error\n");

			return -1;
		}
	}
	//(void)printf("read file header finish.\n");

	/* check if it is the right bin file of original firmware. */
	if ((ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_0 != original_firmware_bin_file_header.fixed_prefix_0) ||
		(ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_1 != original_firmware_bin_file_header.fixed_prefix_1) ||
		(ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_2 != original_firmware_bin_file_header.fixed_prefix_2) ||
		(ORIGINAL_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_3 != original_firmware_bin_file_header.fixed_prefix_3))
	{
		(void)printf("%s is illegal bin file\n", original_firmware_bin_file_name);

		return -1;
	}

	/* open bin file of released firmware. */
	released_firmware_bin_file = fopen(released_firmware_bin_file_name, "w");
	if (NULL == released_firmware_bin_file) {
		perror("fopen() of released bin file");

		return -1;
	}

	/* initialize the key for further decryption. */
	AES_init_ctx(&AES_ctx_decrypted_for_platform, &key_for_platform[0]);

	//(void)printf("decryption start.\n");
	while (!is_original_firmware_bin_file_read_complete) {
		/* read bin file of original firmware. */
		read_items_amount = fread(&data_buf[0], 1, AES_BLOCKLEN, original_firmware_bin_file);
		if (AES_BLOCKLEN != read_items_amount) {
			if (ferror(original_firmware_bin_file)) {
				perror("fread()");

				return -1;
			}

			if (feof(original_firmware_bin_file)) {
				clearerr(original_firmware_bin_file);

				is_original_firmware_bin_file_read_complete = true;
			} else {
				(void)printf("fread() unknown error\n");

				return -1;
			}
		}

		/*
				we have gotten read_items_amount bytes,
			it must be AES_BLOCKLEN,
			because embeded engineers make the size multiple of AES_BLOCKLEN!
		*/
		if (read_items_amount) {
			if (AES_BLOCKLEN > read_items_amount) {
				(void)printf("read_items_amount must be AES_BLOCKLEN\n");

				return -1;
			}

			/* it should be AES_ctx_decrypted_for_platform for decryption. */
			AES_ECB_decrypt(&AES_ctx_decrypted_for_platform, &data_buf[0]);

			/* write bin file of released firmware. */
			write_items_amount = fwrite(&data_buf[0], 1, AES_BLOCKLEN, released_firmware_bin_file);
			if (AES_BLOCKLEN != write_items_amount) {
				if (ferror(released_firmware_bin_file)) {
					perror("fwrite()");

					return -1;
				}
			}
		}
	}
	//(void)printf("decryption finish.\n");

	/* close bin file of released firmware. */
	if (fclose(released_firmware_bin_file)) {
		perror("fclose() of released bin file");

		return -1;
	}

	/* close bin file of original firmware. */
	if (fclose(original_firmware_bin_file)) {
		perror("fclose() of original bin file");

		return -1;
	}

	(void)printf("encrypted original bin file of firmware has been successfully read out\n");
	(void)printf("    file name: %s\n", original_firmware_bin_file_name);
	(void)printf("    year: %d; month: %d; day: %d; hour: %d; minute: %d\n",
		original_firmware_bin_file_header.release_year,
		original_firmware_bin_file_header.release_month,
		original_firmware_bin_file_header.release_day,
		original_firmware_bin_file_header.release_hour,
		original_firmware_bin_file_header.release_minute);
	(void)printf("    version: %d.%d.%d\n",
		original_firmware_bin_file_header.version_major,
		original_firmware_bin_file_header.version_minor,
		original_firmware_bin_file_header.version_revision);
	(void)printf("    developer: %s\n",
		original_firmware_bin_file_header.developer_name);
	(void)printf("    firmware length: %d bytes\n",
		original_firmware_bin_file_header.firmware_length);
	(void)printf("    firmware CRC32: 0x%08x\n",
		original_firmware_bin_file_header.firmware_crc32);

	(void)printf("decrypted released bin file of firmware has been successfully generated\n");
	(void)printf("    file name: %s\n", released_firmware_bin_file_name);



is_reconnect_needed:
	/* below is firmware update by USB communication. */
	/* below is related initialization of USB communication. */
	if (hid_init()) {
		(void)printf("hid_init() error\n");

		return -1;
	}

	target_hid_device_info = hid_enumerate(target_HID_device_VID, target_HID_device_PID);
	if (!target_hid_device_info) {
		(void)printf("hid_enumerate() error\n");

		ret = -1;
		goto exit_1;
	}

	target_hid_device = hid_open(target_HID_device_VID, target_HID_device_PID, NULL);
	if (!target_hid_device) {
		(void)printf("hid_open() error\n");

		ret = -1;
		goto exit_2;
	}
	/* above is related initialization of USB communication. */

	/* below is firmware update of USB communication. */
	/* bootloader code enter command: send. */
	hid_data_buf[0] = 0;
	for (i = 0; bootloader_code_enter_command_string[i]; i++) {
		hid_data_buf[1 + i] = bootloader_code_enter_command_string[i];
	}
	hid_data_buf[1 + i] = 0;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("bootloader code enter command: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* bootloader code enter command: receive. */
	/*
			if MCU is in application code,
		the command should not have response because USB communication should be disconnected for a while.
			if MCU is in bootloader code,
		the response will return error code "DFU_PACKET_ERROR_UNSUPPORTED_COMMAND".
	*/
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (-1 == read_hid_data_amount) {
		(void)printf("bootloader code enter command: jumping from application code to bootloader code...\n");

		is_reconnect_needed = true;

		goto exit_3;
	} else if (USB_COMMUNICATION_RX_DATA_LENGTH == read_hid_data_amount) {
		DFU_packet_error_code = hid_data_buf[0];
		if (DFU_PACKET_ERROR_UNSUPPORTED_COMMAND == DFU_packet_error_code) {
			(void)printf("bootloader code enter command: already in bootloader code...\n");
		} else {
			(void)printf("bootloader code enter command: unknown error: read_hid_data_amount = %d, DFU_packet_error_code = %d\n", read_hid_data_amount, DFU_packet_error_code);

			ret = -1;
			goto exit_3;
		}
	} else {
		(void)printf("bootloader code enter command: unknown error: read_hid_data_amount = %d, DFU_packet_error_code = %d\n", read_hid_data_amount, DFU_packet_error_code);

		ret = -1;
		goto exit_3;
	}

	/* DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: send. */
	hid_data_buf[0] = 0;
	hid_data_buf[1] = DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: receive. */
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (USB_COMMUNICATION_RX_DATA_LENGTH != read_hid_data_amount) {
		(void)printf("DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: receive error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: resolve. */
	DFU_packet_error_code = hid_data_buf[0];
	if (DFU_PACKET_ERROR_OK != DFU_packet_error_code) {
		(void)printf("DFU_PACKET_GET_ORIGINAL_PERMISSION_KEY: resolve error: DFU_packet_error_code = %d\n", DFU_packet_error_code);

		ret = -1;
		goto exit_3;
	}
	original_permission_key = *(unsigned int *)&hid_data_buf[1];
	CRC32_repeat_time       = hid_data_buf[5];
	//(void)printf("original_permission_key = %d\n", original_permission_key);
	//(void)printf("CRC32_repeat_time = %d\n", CRC32_repeat_time);
	calculated_permission_key = original_permission_key;
	for (i = 0; i < CRC32_repeat_time; i++) {
		calculated_permission_key = crc32((unsigned char *)&calculated_permission_key, 4);
	}

	/* DFU_PACKET_INITIAL_PREPARE: send. */
	hid_data_buf[0]                   = 0;
	hid_data_buf[1]                   = DFU_PACKET_INITIAL_PREPARE;
	*(unsigned int *)&hid_data_buf[2] = original_firmware_bin_file_header.firmware_length;
	*(unsigned int *)&hid_data_buf[6] = calculated_permission_key;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("DFU_PACKET_INITIAL_PREPARE: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_INITIAL_PREPARE: receive. */
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (USB_COMMUNICATION_RX_DATA_LENGTH != read_hid_data_amount) {
		(void)printf("DFU_PACKET_INITIAL_PREPARE: receive error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_INITIAL_PREPARE: resolve. */
	DFU_packet_error_code = hid_data_buf[0];
	if (DFU_PACKET_ERROR_OK != DFU_packet_error_code) {
		(void)printf("DFU_PACKET_INITIAL_PREPARE: resolve error: DFU_packet_error_code = %d\n", DFU_packet_error_code);

		ret = -1;
		goto exit_3;
	}

	/* DFU_PACKET_START_UPDATE: send. */
	hid_data_buf[0] = 0;
	hid_data_buf[1] = DFU_PACKET_START_UPDATE;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("DFU_PACKET_START_UPDATE: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_START_UPDATE: receive. */
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (USB_COMMUNICATION_RX_DATA_LENGTH != read_hid_data_amount) {
		(void)printf("DFU_PACKET_START_UPDATE: receive error: read_hid_data_amount = %d\n", read_hid_data_amount);

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_START_UPDATE: resolve. */
	DFU_packet_error_code = hid_data_buf[0];
	if (DFU_PACKET_ERROR_OK != DFU_packet_error_code) {
		(void)printf("DFU_PACKET_START_UPDATE: resolve error: DFU_packet_error_code = %d\n", DFU_packet_error_code);

		ret = -1;
		goto exit_3;
	}

	/* open bin file of released firmware. */
	released_firmware_bin_file = fopen(released_firmware_bin_file_name, "r");
	if (NULL == released_firmware_bin_file) {
		perror("fopen() of released bin file");

		ret = -1;
		goto exit_3;
	}
	//(void)printf("firmware update start.\n");
	while (!is_released_firmware_bin_file_read_complete) {
		/* read bin file of released firmware. */
		read_items_amount = fread(&hid_data_buf[5], 1, AES_BLOCKLEN * 3, released_firmware_bin_file);
		if ((AES_BLOCKLEN * 3) != read_items_amount) {
			if (ferror(released_firmware_bin_file)) {
				perror("fread()");

				ret = -1;
				goto exit_3;
			}

			if (feof(released_firmware_bin_file)) {
				clearerr(released_firmware_bin_file);

				is_released_firmware_bin_file_read_complete = true;
			} else {
				(void)printf("fread() unknown error\n");

				ret = -1;
				goto exit_3;
			}
		}

		/*
				we have gotten read_items_amount bytes,
			it must be (AES_BLOCKLEN * 1) / (AES_BLOCKLEN * 2) / (AES_BLOCKLEN * 3),
			because embeded engineers make the size multiple of AES_BLOCKLEN!
		*/
		if (read_items_amount) {
			/* DFU_PACKET_UPDATING: send. */
			hid_data_buf[0]                     = 0;
			hid_data_buf[1]                     = DFU_PACKET_UPDATING;
			hid_data_buf[2]                     = read_items_amount;
			*(unsigned short *)&hid_data_buf[3] = frame_number++;
			write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
			if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
				(void)printf("DFU_PACKET_UPDATING: send error\n");

				ret = -1;
				goto exit_3;
			}
			/* DFU_PACKET_UPDATING: receive. */
			read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
			if (USB_COMMUNICATION_RX_DATA_LENGTH != read_hid_data_amount) {
				(void)printf("DFU_PACKET_UPDATING: receive error\n");

				ret = -1;
				goto exit_3;
			}
			/* DFU_PACKET_UPDATING: resolve. */
			DFU_packet_error_code = hid_data_buf[0];
			if (DFU_PACKET_ERROR_OK != DFU_packet_error_code) {
				(void)printf("DFU_PACKET_UPDATING: resolve error: DFU_packet_error_code = %d\n", DFU_packet_error_code);

				ret = -1;
				goto exit_3;
			}

			read_items_amount_downloaded += read_items_amount;
			process_bar = 100 * read_items_amount_downloaded / original_firmware_bin_file_header.firmware_length;
		}
	}
	//(void)printf("firmware update finish.\n");
	/* close bin file of released firmware. */
	if (fclose(released_firmware_bin_file)) {
		perror("fclose() of released bin file");

		ret = -1;
		goto exit_3;
	}

	/* DFU_PACKET_CHECK_CRC32: send. */
	hid_data_buf[0]                   = 0;
	hid_data_buf[1]                   = DFU_PACKET_CHECK_CRC32;
	*(unsigned int *)&hid_data_buf[2] = original_firmware_bin_file_header.firmware_crc32;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("DFU_PACKET_CHECK_CRC32: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_CHECK_CRC32: receive. */
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (USB_COMMUNICATION_RX_DATA_LENGTH != read_hid_data_amount) {
		(void)printf("DFU_PACKET_CHECK_CRC32: receive error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_CHECK_CRC32: resolve. */
	DFU_packet_error_code = hid_data_buf[0];
	if (DFU_PACKET_ERROR_OK != DFU_packet_error_code) {
		(void)printf("DFU_PACKET_CHECK_CRC32: resolve error: DFU_packet_error_code = %d\n", DFU_packet_error_code);

		ret = -1;
		goto exit_3;
	}

	/* DFU_PACKET_ENABLE_APPLICATION_CODE: send. */
	hid_data_buf[0] = 0;
	hid_data_buf[1] = DFU_PACKET_ENABLE_APPLICATION_CODE;
	write_hid_data_amount = hid_write(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_TX_DATA_LENGTH);
	if (USB_COMMUNICATION_TX_DATA_LENGTH != write_hid_data_amount) {
		(void)printf("DFU_PACKET_ENABLE_APPLICATION_CODE: send error\n");

		ret = -1;
		goto exit_3;
	}
	/* DFU_PACKET_ENABLE_APPLICATION_CODE: receive. */
	/* the command should not have response because USB communication should be disconnected for a while. */
	read_hid_data_amount = hid_read_timeout(target_hid_device, &hid_data_buf[0], USB_COMMUNICATION_RX_DATA_LENGTH, USB_COMMUNICATION_TIMEOUT_IN_MILLISECONDS);
	if (-1 == read_hid_data_amount) {
		(void)printf("DFU_PACKET_ENABLE_APPLICATION_CODE: firmware update OK\n");
	} else{ 
		(void)printf("DFU_PACKET_ENABLE_APPLICATION_CODE: firmware update FAIL\n");

		ret = -1;
		goto exit_3;
	}
	/* above is firmware update of USB communication. */

	/* below is related finalization of USB communication. */
exit_3:
	hid_close(target_hid_device);

exit_2:
	hid_free_enumeration(target_hid_device_info);

exit_1:
	if (hid_exit()) {
		(void)printf("hid_exit() error\n");

		return -1;
	}
	/* above is related finalization of USB communication. */

	/*
			if MCU is in application code rather than bootloader code,
		when we request firmware update by USB communication,
		USB will disconnect for a while,
		so it is needed to reconnect.
	*/
	if (is_reconnect_needed) {
		is_reconnect_needed = false;

		/* it is needed to wait for a while for USB reconnect. */
		DELAY_S(3);

		goto is_reconnect_needed;
	}

	return ret;
}

