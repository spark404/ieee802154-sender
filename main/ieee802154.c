//
// Created by Hugo Trippaers on 02/06/2023.
//

#include <string.h>

#include "esp_log.h"
#include "mbedtls/ccm.h"

#include "ieee802154.h"

#define TAG "ieee802154"

#define AES_CCM_NONCE_SIZE 13
uint8_t  esl_key[] = {0xD3, 0x06, 0xD9, 0x34, 0x8E, 0x29, 0xE5, 0xE3, 0x58, 0xBF, 0x29, 0x34, 0x81, 0x20, 0x02, 0xC1};

static mbedtls_ccm_context ctx;
static void reverse_memcpy(uint8_t *restrict dst, const uint8_t *restrict src, size_t n);

uint8_t iee802154_header(const uint16_t *src_pan, ieee802154_address_t *src, const uint16_t *dst_pan, ieee802154_address_t *dst, uint8_t *header, uint8_t header_length) {
    uint8_t frame_header_len = 2;
    mac_fcs_t frame_header = {
        .frameType = FRAME_TYPE_DATA,
        .secure = false,
        .framePending = false,
        .ackReqd = false,
        .panIdCompressed = false,
        .rfu1 = false,
        .sequenceNumberSuppression = false,
        .informationElementsPresent = false,
        .destAddrType = dst->mode,
        .frameVer = FRAME_VERSION_STD_2003,
        .srcAddrType = src->mode
    };

    bool src_present = src != NULL && src->mode != ADDR_MODE_NONE;
    bool dst_present = dst != NULL && dst->mode != ADDR_MODE_NONE;
    bool src_pan_present = src_pan != NULL;
    bool dst_pan_present = dst_pan != NULL;

    if (!frame_header.sequenceNumberSuppression) {
        frame_header_len += 1;
    }

    if (dst_pan_present) {
        frame_header_len += 2;
    }

    if (frame_header.destAddrType == ADDR_MODE_SHORT) {
        frame_header_len += 2;
    } else if (frame_header.destAddrType == ADDR_MODE_LONG) {
        frame_header_len += 8;
    }

    if (src_pan_present) {
        frame_header_len +=2;
    }

    if (frame_header.srcAddrType == ADDR_MODE_SHORT) {
        frame_header_len += 2;
    } else if (frame_header.srcAddrType == ADDR_MODE_LONG) {
        frame_header_len += 8;
    }

    if (header_length < frame_header_len) {
        return 0;
    }

    uint8_t position = 0;
    memcpy(&header[position], &frame_header, sizeof frame_header);
    position += 2;

    if (!frame_header.sequenceNumberSuppression) {
        header[position++] = 0;
    }

    if (dst_pan != NULL) {
        memcpy(&header[position], dst_pan, sizeof(uint16_t));
        position += 2;
    }

    if (frame_header.destAddrType == ADDR_MODE_SHORT) {
        memcpy(&header[position], &dst->short_address, sizeof dst->short_address);
        position += 2;
    } else if (frame_header.destAddrType == ADDR_MODE_LONG) {
        reverse_memcpy(&header[position], (uint8_t *)&dst->long_address, sizeof dst->long_address);
        position += 8;
    }

    if (src_pan != NULL) {
        memcpy(&header[position], src_pan, sizeof(uint16_t));
        position += 2;
    }

    if (frame_header.srcAddrType == ADDR_MODE_SHORT) {
        memcpy(&header[position], &src->short_address, sizeof src->short_address);
        position += 2;
    } else if (frame_header.srcAddrType == ADDR_MODE_LONG) {
        reverse_memcpy(&header[position], (uint8_t *)&src->long_address, sizeof src->long_address);
        position += 8;
    }

    return position;
}

esp_err_t encoder_init() {
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, esl_key, sizeof(esl_key) * 8);

    if (ret != 0) {
        ESP_EARLY_LOGE(TAG, "Failed to set key, rc = %d", ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

uint8_t encode_packet(uint32_t timestamp, uint8_t* plaintext, uint8_t plaintext_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *output, uint8_t output_length) {
    uint8_t timestamp_length = 4;
    uint8_t tag_length = 4;

    if (output == NULL) {
        ESP_LOGE("esl-encode", "Invalid output buffer");
        return 0;
    }

    if (output_length < plaintext_length + timestamp_length + tag_length) {
        ESP_LOGE("esl-encode", "output buffer too small");
        return 0;
    }

    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};

    // Nonce: | timestamp (4 bytes) | source addr (8 bytes) | 0 (1 byte) |
    memcpy(nonce, &timestamp, timestamp_length);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }

    int ret = mbedtls_ccm_encrypt_and_tag(&ctx, plaintext_length,
                                          nonce, AES_CCM_NONCE_SIZE,
                                          header, header_length,
                                          plaintext, output,
                                          output + plaintext_length, tag_length);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to encrypt packet, rc = %d", ret);
        return 0;
    }

    ESP_LOGD(TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, nonce, AES_CCM_NONCE_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Tag:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, output + plaintext_length, tag_length, ESP_LOG_DEBUG);

    // Insert the timestamp into the buffer
    memcpy(output+plaintext_length+tag_length, &timestamp, timestamp_length);

    // Return the length
    return plaintext_length + timestamp_length + tag_length;
}


static void reverse_memcpy(uint8_t *restrict dst, const uint8_t *restrict src, size_t n)
{
    size_t i;

    for (i=0; i < n; ++i) {
        dst[n - 1 - i] = src[i];
    }
}