#include <string.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_ieee802154.h>
#include <esp_log.h>
#include <esp_phy_init.h>
#include <math.h>
#include "mbedtls/ccm.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "802154_proto.h"
#include "ieee802154.h"
#include "esp_esl.h"
#include "sdkconfig.h"
#include "esl_proto.h"

#define TAG "main"
#define RADIO_TAG "ieee802154"

#define PANID 0x4447
#define CHANNEL 11

#define SHORT_BROADCAST 0xFFFF
#define SHORT_NOT_CONFIGURED 0xFFFE
#define SHORT_SENDER 0x1111
#define AES_CCM_NONCE_SIZE 13
#define PAN_BROADCAST 0xFFFF

#define FCS_LEN 2

typedef uint16_t crc;

uint8_t  my_esl_key[] = {0xD3, 0x06, 0xD9, 0x34, 0x8E, 0x29, 0xE5, 0xE3, 0x58, 0xBF, 0x29, 0x34, 0x81, 0x20, 0x02, 0xC1};
uint16_t my_esl_pan   = 0x4447;


#define WIDTH  (8 * sizeof(crc))
#define TOPBIT (1 << (WIDTH - 1))
#define POLYNOMIAL 0x1021

crc crcSlow(uint8_t const message[], int nBytes);

typedef struct {
    uint8_t length;
    uint8_t data[256];
} packet_t;


QueueHandle_t packet_rx_queue = NULL;
QueueHandle_t esl_packet_queue = NULL;
mbedtls_ccm_context ctx;

static uint8_t test_frame[] = {
        0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, 0x08, 0x00, 0x28, 0x0a, 0x00, 0x80,
        0x00, 0x28, 0x01, 0x1d, 0x00, 0x43, 0x00, 0x02, 0x00, 0xc8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef struct esl_packet {
    uint8_t packet_type;
    uint8_t source_addr[8];
    uint8_t dest_addr[8];
    union {
        uint8_t raw[64];
        struct TagInfo tag_info;          // PKT_ASSOC_REQ
        struct AssocInfo assoc_info;      // PKT_ASSOC_RESP
        struct CheckinInfo check_in_info; // PKT_CHECKIN
        struct PendingInfo pending_info;  // PKT_CHECKOUT
    };
} __attribute__((packed, aligned(1))) esl_packet_t;

void parse_esl_packet(uint8_t* data, uint8_t length, uint8_t* src_addr, uint8_t* dst_addr) {
    esl_packet_t esl_packet;

    esl_packet.packet_type = data[0];
    memcpy(&esl_packet.source_addr, src_addr, 8);
    memcpy(&esl_packet.dest_addr, dst_addr, 8);
    memcpy(&esl_packet.raw, &data[1], length-1);

    // TODO Validate combination of packet length and type

    if (xQueueSendToBack(esl_packet_queue, &esl_packet, pdMS_TO_TICKS(50)) != pdTRUE) {
        ESP_LOGE("main", "Failed to queue esl packet");
    }
}

void decode_packet(uint8_t* header, uint8_t header_length, uint8_t* data, uint8_t data_length, uint8_t* src_addr, uint8_t* dst_addr) {
    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};
    memcpy(nonce, data + data_length - 4, 4);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }
    uint8_t* ciphertext        = &data[0];
    uint8_t  ciphertext_length = data_length - 4 - 4;  // 4 bytes tag, 4 bytes nonce
    uint8_t* tag               = &data[ciphertext_length];
    uint8_t  tag_length        = 4;

    uint8_t decoded[256];

    ESP_LOGI(RADIO_TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX(RADIO_TAG, nonce, AES_CCM_NONCE_SIZE);

    ESP_LOGI(RADIO_TAG, "Tag:");
    ESP_LOG_BUFFER_HEX(RADIO_TAG, tag, 4);

    ESP_LOGI(RADIO_TAG, "Encrypted:");
    esp_log_buffer_hexdump_internal(RADIO_TAG, data, data_length, ESP_LOG_INFO);

    int ret = mbedtls_ccm_auth_decrypt(&ctx, ciphertext_length, nonce, AES_CCM_NONCE_SIZE, header, header_length, ciphertext, decoded, tag, tag_length);

    if (ret != 0) {
        ESP_EARLY_LOGE(RADIO_TAG, "Failed to decrypt packet, rc = %d", ret);
        return;
    }


    ESP_LOGI(RADIO_TAG, "Plain:");
    esp_log_buffer_hexdump_internal(RADIO_TAG, decoded, ciphertext_length, ESP_LOG_INFO);

    parse_esl_packet(decoded, ciphertext_length, src_addr, dst_addr);
}

void handle_packet(uint8_t* packet, uint8_t packet_length) {
    if (packet_length < sizeof(mac_fcs_t)) return;  // Can't be a packet if it's shorter than the frame control field

    uint8_t position = 0;

    mac_fcs_t* fcs = (mac_fcs_t*) &packet[position];
    position += sizeof(uint16_t);

    ESP_LOGI(RADIO_TAG, "Frame type:                   %x", fcs->frameType);
    ESP_LOGI(RADIO_TAG, "Security Enabled:             %s", fcs->secure ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Frame pending:                %s", fcs->framePending ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Acknowledge request:          %s", fcs->ackReqd ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "PAN ID Compression:           %s", fcs->panIdCompressed ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Reserved:                     %s", fcs->rfu1 ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Sequence Number Suppression:  %s", fcs->sequenceNumberSuppression ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Information Elements Present: %s", fcs->informationElementsPresent ? "True" : "False");
    ESP_LOGI(RADIO_TAG, "Destination addressing mode:  %x", fcs->destAddrType);
    ESP_LOGI(RADIO_TAG, "Frame version:                %x", fcs->frameVer);
    ESP_LOGI(RADIO_TAG, "Source addressing mode:       %x", fcs->srcAddrType);

    if (fcs->panIdCompressed == false) {
        ESP_LOGE(RADIO_TAG, "PAN identifier not compressed, ignoring packet");
        // return;
    }

    if (fcs->rfu1) {
        ESP_LOGE(RADIO_TAG, "Reserved field 1 is set, ignoring packet");
        return;
    }

    if (fcs->sequenceNumberSuppression) {
        ESP_LOGE(RADIO_TAG, "Sequence number suppressed, ignoring packet");
        return;
    }

    if (fcs->informationElementsPresent) {
        ESP_LOGE(RADIO_TAG, "Information elements present, ignoring packet");
        return;
    }

    if (fcs->frameVer != 0x0) {
        ESP_LOGE(RADIO_TAG, "Unsupported frame version, ignoring packet");
        return;
    }

    switch (fcs->frameType) {
        case FRAME_TYPE_BEACON:
        {
            ESP_LOGI(RADIO_TAG, "Beacon");
            break;
        }
        case FRAME_TYPE_DATA:
        {
            uint8_t sequence_number = packet[position];
            position += sizeof(uint8_t);
            ESP_LOGI(RADIO_TAG, "Data (%u)", sequence_number);

            uint16_t pan_id         = 0;
            uint8_t  dst_addr[8]    = {0};
            uint8_t  src_addr[8]    = {0};
            uint16_t short_dst_addr = 0;
            uint16_t short_src_addr = 0;
            bool     broadcast      = false;

            switch (fcs->destAddrType) {
                case ADDR_MODE_NONE:
                {
                    ESP_LOGI(RADIO_TAG, "Without PAN ID or address field");
                    break;
                }
                case ADDR_MODE_SHORT:
                {
                    pan_id = *((uint16_t*) &packet[position]);
                    position += sizeof(uint16_t);
                    short_dst_addr = *((uint16_t*) &packet[position]);
                    position += sizeof(uint16_t);
                    if (pan_id == 0xFFFF && short_dst_addr == 0xFFFF) {
                        broadcast = true;
                        pan_id    = *((uint16_t*) &packet[position]);  // srcPan
                        position += sizeof(uint16_t);
                        ESP_LOGI(RADIO_TAG, "Broadcast on PAN %04x", pan_id);
                    } else {
                        ESP_LOGI(RADIO_TAG, "On PAN %04x to short address %04x", pan_id, short_dst_addr);
                    }
                    break;
                }
                case ADDR_MODE_LONG:
                {
                    pan_id = *((uint16_t*) &packet[position]);
                    position += sizeof(uint16_t);
                    for (uint8_t idx = 0; idx < sizeof(dst_addr); idx++) {
                        dst_addr[idx] = packet[position + sizeof(dst_addr) - 1 - idx];
                    }
                    position += sizeof(dst_addr);
                    ESP_LOGI(RADIO_TAG, "On PAN %04x to long address %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", pan_id, dst_addr[0],
                             dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5], dst_addr[6], dst_addr[7]);
                    break;
                }
                default:
                {
                    ESP_LOGE(RADIO_TAG, "With reserved destination address type, ignoring packet");
                    return;
                }
            }

            switch (fcs->srcAddrType) {
                case ADDR_MODE_NONE:
                {
                    ESP_LOGI(RADIO_TAG, "Originating from the PAN coordinator");
                    break;
                }
                case ADDR_MODE_SHORT:
                {
                    short_src_addr = *((uint16_t*) &packet[position]);
                    position += sizeof(uint16_t);
                    ESP_LOGI(RADIO_TAG, "Originating from short address %04x", short_src_addr);
                    break;
                }
                case ADDR_MODE_LONG:
                {
                    for (uint8_t idx = 0; idx < sizeof(src_addr); idx++) {
                        src_addr[idx] = packet[position + sizeof(src_addr) - 1 - idx];
                    }
                    position += sizeof(src_addr);
                    ESP_LOGI(RADIO_TAG, "Originating from long address %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", src_addr[0], src_addr[1],
                             src_addr[2], src_addr[3], src_addr[4], src_addr[5], src_addr[6], src_addr[7]);
                    break;
                }
                default:
                {
                    ESP_LOGE(RADIO_TAG, "With reserved source address type, ignoring packet");
                    return;
                }
            }

            uint8_t* header        = &packet[0];
            uint8_t  header_length = position;
            uint8_t* data          = &packet[position];
            uint8_t  data_length   = packet_length - position - sizeof(uint16_t);
            position += data_length;

            ESP_LOGI(RADIO_TAG, "Data length: %u", data_length);

            uint16_t checksum = *((uint16_t*) &packet[position]);

            ESP_LOGI(RADIO_TAG, "Checksum: %04x", checksum);

            ESP_LOGI(RADIO_TAG, "PAN %04x S %04x %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X to %04x %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X %s", pan_id,
                     short_src_addr, src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5], src_addr[6], src_addr[7],
                     short_dst_addr, dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5], dst_addr[6], dst_addr[7],
                     broadcast ? "BROADCAST" : "");

            if (broadcast)
                for (uint8_t idx = 0; idx < 8; idx++) dst_addr[idx] = 0xFF;

            if (pan_id != my_esl_pan) return;  // Filter, only process electronic shelf label packets

            decode_packet(header, header_length, data, data_length, src_addr, dst_addr);
            break;
        }
        case FRAME_TYPE_ACK:
        {
            uint8_t sequence_number = packet[position++];
            ESP_LOGI(RADIO_TAG, "Ack (%u)", sequence_number);
            break;
        }
        default:
        {
            ESP_LOGE(RADIO_TAG, "Packet ignored because of frame type (%u)", fcs->frameType);
            break;
        }
    }
}
#define ESL_HANDLER_TASK_TAG "esl_handler_task"
typedef struct {
    QueueHandle_t handle;
} esl_handler_task_config_t;

static void esl_handler_task(void *pvParameters) {
    if (pvParameters == NULL) {
        ESP_LOGE(ESL_HANDLER_TASK_TAG, "No parameters for task");
        vTaskDelete(NULL);
    }

    esl_handler_task_config_t *config = (esl_handler_task_config_t *)pvParameters;
    QueueHandle_t queue_handle = config->handle;

    ESP_LOGI(ESL_HANDLER_TASK_TAG, "Starting ESL handler task");

    esl_packet_t packet;

    while (xQueueReceive(queue_handle, &packet, portMAX_DELAY) != pdFALSE) {
        uint8_t *src_addr = packet.source_addr;
        uint8_t *dst_addr = packet.dest_addr;
        printf("[%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X] to [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]: ", src_addr[0], src_addr[1], src_addr[2], src_addr[3],
               src_addr[4], src_addr[5], src_addr[6], src_addr[7], dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5], dst_addr[6],
               dst_addr[7]);

        switch (packet.packet_type) {
            case PKT_ASSOC_REQ:
            {
                struct TagInfo* tagInfo = &packet.tag_info;
                printf("Assoc request  proto v%u, sw v%llu, hw %04x, batt %u mV, w %u px (%u mm), h %u px (%u mm), c %04x, maxWait %u ms, screenType %u",
                       tagInfo->protoVer, tagInfo->state.swVer, tagInfo->state.hwType, tagInfo->state.batteryMv, tagInfo->screenPixWidth,
                       tagInfo->screenMmWidth, tagInfo->screenPixHeight, tagInfo->screenMmHeight, tagInfo->compressionsSupported, tagInfo->maxWaitMsec,
                       tagInfo->screenType);

                uint8_t myaddr[8];
                esp_ieee802154_get_extended_address(myaddr);
                break;
            }
            case PKT_ASSOC_RESP:
            {
                struct AssocInfo* assocInfo = &packet.assoc_info;
                printf(
                        "Assoc response: checkin delay %lu, retry delay %lu, failedCheckinsTillBlank %u, failedCheckinsTillDissoc %u, newKey %08lx %08lx %08lx "
                        "%08lx",
                        assocInfo->checkinDelay, assocInfo->retryDelay, assocInfo->failedCheckinsTillBlank, assocInfo->failedCheckinsTillDissoc,
                        assocInfo->newKey[0], assocInfo->newKey[1], assocInfo->newKey[2], assocInfo->newKey[3]);
                break;
            }
            case PKT_CHECKIN:
            {
                struct CheckinInfo* checkinInfo = &packet.check_in_info;
                printf("Checkin: sw v%llu, hw %04x, batt %u mV, LQI %u, RSSI %d, temperature %u *c", checkinInfo->state.swVer, checkinInfo->state.hwType,
                       checkinInfo->state.batteryMv, checkinInfo->lastPacketLQI, checkinInfo->lastPacketRSSI, checkinInfo->temperature - CHECKIN_TEMP_OFFSET);

                break;
            }
            case PKT_CHECKOUT:
            {
                struct PendingInfo* pendingInfo = &packet.pending_info;
                printf("Checkout: image version %llu, image size %lu, os version %llu, os size %lu", pendingInfo->imgUpdateVer, pendingInfo->imgUpdateSize,
                       pendingInfo->osUpdateVer, pendingInfo->osUpdateSize);
                break;
            }
#ifdef NOT_READY
                case PKT_CHUNK_REQ:
                {
                    if (length < sizeof(struct ChunkReqInfo)) {
                        printf("Chunk request, too short\n");
                        return;
                    }
                    struct ChunkReqInfo* chunkReqInfo = (struct ChunkReqInfo*) packet;
                    printf("Chunk request: version %llu, offset %lu, len %u, os update %s", chunkReqInfo->versionRequested, chunkReqInfo->offset, chunkReqInfo->len,
                           chunkReqInfo->osUpdatePlz ? "yes" : "no");
                    break;
                }
            case PKT_CHUNK_RESP:
                {
                    if (length < sizeof(struct ChunkInfo)) {
                        printf("Chunk response, too short\n");
                        return;
                    }
                    struct ChunkInfo* chunkInfo = (struct ChunkInfo*) packet;
                    printf("Chunk response: offset %lu, os update %s, ", chunkInfo->offset, chunkInfo->osUpdatePlz ? "yes" : "no");
                    for (uint8_t idx = 0; idx < length - sizeof(struct ChunkInfo); idx++) {
                        printf("%02x", chunkInfo->data[idx]);
                    }
                    break;
                }
#endif
            default:
            {
                printf("Unknown ESL packet type (%u)", packet.packet_type);
            }
        }
        printf("\n");
    }

    ESP_LOGI(ESL_HANDLER_TASK_TAG, "Shutdown ESL handler task");
    vTaskDelete(NULL);
}

void packet_handle_task(void *pvParameters) {
    static packet_t packet;
    while (true) {
        if (xQueueReceive(packet_rx_queue, (void *) &packet, portMAX_DELAY) == pdTRUE) {
            handle_packet(packet.data, packet.length);
        }
    }
}

void IRAM_ATTR esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_frame_info) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx OK, sent %d bytes, ack %d", frame[0], ack != NULL);
}

void IRAM_ATTR esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx failed, error %d", error);
}

void IRAM_ATTR esp_ieee802154_transmit_sfd_done(uint8_t *frame) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx sfd done");
}

void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx OK, received %d bytes", frame[0]);
    static packet_t packet;
    packet.length = frame[0];
    memcpy(packet.data, &frame[1], packet.length);
    xQueueSendFromISR(packet_rx_queue, (void*) &packet, pdFALSE);
}

void IRAM_ATTR esp_ieee802154_receive_failed(uint16_t error) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx failed, error %d", error);
}

void IRAM_ATTR esp_ieee802154_receive_sfd_done(void) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx sfd done, Radio state: %d", esp_ieee802154_get_state());
}

void app_main() {
    ESP_LOGI(TAG, "Initializing NVS from flash...");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_LOGI(TAG, "Initializing mbedtls...");
    ESP_ERROR_CHECK(esp_esl_aes_ccm_init());

    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, my_esl_key, sizeof(my_esl_key) * 8);

    if (ret != 0) {
        ESP_EARLY_LOGE(RADIO_TAG, "Failed to set key, rc = %d", ret);
        return;
    }

    ESP_LOGI(TAG, "Initializing queues and tasks...");
    packet_rx_queue = xQueueCreate(8, 257);
    esl_packet_queue  = xQueueCreate(8, sizeof(esl_packet_t));

    esl_handler_task_config_t config = {
            .handle = esl_packet_queue
    };
    TaskHandle_t esl_handler_task_handle;
    if (xTaskCreate(esl_handler_task, "esl_handler_task", 8192, &config, 10, &esl_handler_task_handle) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to start esl_handler_task");
        return;
    }

    TaskHandle_t packet_handler_task_handle;
    if (xTaskCreate(packet_handle_task, "packet_handler_task", 8192, NULL, 9, &packet_handler_task_handle) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to start packet_handle_task");
        return;
    }

    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));

    ESP_ERROR_CHECK(esp_ieee802154_set_panid(PANID));
    ESP_ERROR_CHECK(esp_ieee802154_set_coordinator(false));

    ESP_ERROR_CHECK(esp_ieee802154_set_channel(CHANNEL));

    esp_phy_calibration_data_t cal_data;
    ESP_ERROR_CHECK(esp_phy_load_cal_data_from_nvs(&cal_data));

    // Set long address to the mac address (with 0xff padding at the end)
    // Set short address to unconfigured
    uint8_t long_address[8];
    memcpy(&long_address, cal_data.mac, 6);
    long_address[6] = 0xff;
    long_address[7] = 0xfe;
    esp_ieee802154_set_extended_address(long_address);
    esp_ieee802154_set_short_address(SHORT_SENDER);

    ESP_ERROR_CHECK(esp_ieee802154_receive());

    uint8_t radio_long_address[8];
    esp_ieee802154_get_extended_address(radio_long_address);
    ESP_LOGI(TAG, "Simulator ready, panId=0x%04x, channel=%d, long=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, short=%04x",
             esp_ieee802154_get_panid(), esp_ieee802154_get_channel(),
             radio_long_address[0], radio_long_address[1], radio_long_address[2], radio_long_address[3],
             radio_long_address[4], radio_long_address[5], radio_long_address[6], radio_long_address[7],
             esp_ieee802154_get_short_address());

    uint8_t packet[127];
    uint16_t src_pan = 0x4447;
    ieee802154_address_t src = {
            .mode = ADDR_MODE_LONG,
            .long_address = {
                    radio_long_address[0], radio_long_address[1], radio_long_address[2], radio_long_address[3],
                    radio_long_address[4], radio_long_address[5], radio_long_address[6], radio_long_address[7]
            }
    };
    uint16_t dst_pan = PAN_BROADCAST;
    ieee802154_address_t dst = {
        .mode = ADDR_MODE_SHORT,
        .short_address = SHORT_BROADCAST
    };


    // All done, the rest is up to handlers
    while (true) {
        uint32_t timestamp = (uint32_t) trunc((xTaskGetTickCount() / (double)xPortGetTickRateHz()) * 1000);
        uint8_t *hdr = &packet[1];
        uint8_t hdr_len = iee802154_header(&src_pan, &src, &dst_pan, &dst, hdr, 126);

        uint8_t *payload = &packet[1 + hdr_len];
        uint8_t payload_len = esp_esl_aes_ccm_encode(timestamp, test_frame, sizeof(test_frame), hdr, hdr_len, src.long_address, payload, 126 - hdr_len);

        // Add FCS
        crc v = crcSlow(&packet[1], hdr_len + payload_len);
        packet[hdr_len + payload_len + 1] = (v >> 8) & 0xFF;
        packet[hdr_len + payload_len + 2] = v & 0xFF;

        packet[0] = hdr_len + payload_len + FCS_LEN;
        ESP_LOGI(TAG, "Packet: len=%d, hdr=%d, payload=%d", packet[0], hdr_len, payload_len);
        ESP_LOG_BUFFER_HEX(TAG, packet, packet[0] + 1);
        esp_ieee802154_transmit(packet, false);

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

crc crcSlow(uint8_t const message[], int nBytes)
{
    crc  remainder = 0;
    for (int byte = 0; byte < nBytes; ++byte)
    {
        remainder ^= (message[byte] << (WIDTH - 8));
        for (uint8_t bit = 8; bit > 0; --bit)
        {
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }
    }
    return (remainder);
}
