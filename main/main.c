#include <string.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_ieee802154.h>
#include <esp_log.h>
#include <esp_phy_init.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ieee802154.h"
#include "sdkconfig.h"

#define TAG "main"
#define RADIO_TAG "ieee802154"

#define PANID 0x4242
#define CHANNEL 11

#define SHORT_BROADCAST 0xFFFF
#define SHORT_NOT_CONFIGURED 0xFFFE
#define SHORT_SENDER 0x1111

#define PAN_BROADCAST 0xFFFF

#define FCS_LEN 2

static uint8_t test_frame[] = {
        0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, 0x08, 0x00, 0x28, 0x0a, 0x00, 0x80,
        0x00, 0x28, 0x01, 0x1d, 0x00, 0x43, 0x00, 0x02, 0x00, 0xc8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_frame_info) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx OK, sent %d bytes, ack %d", frame[0], ack != NULL);
}

void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx failed, error %d", error);
}

void esp_ieee802154_transmit_sfd_done(uint8_t *frame) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx sfd done");
}

void app_main() {
    ESP_LOGI(TAG, "Initializing NVS from flash...");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_ERROR_CHECK(encoder_init());

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

    uint8_t radio_long_address[8];
    esp_ieee802154_get_extended_address(radio_long_address);
    ESP_LOGI(TAG, "Sender ready, panId=0x%04x, channel=%d, long=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, short=%04x",
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
        uint8_t payload_len = encode_packet(timestamp, test_frame, sizeof(test_frame), hdr, hdr_len, src.long_address, payload, 126 - hdr_len);

        packet[0] = hdr_len + payload_len + FCS_LEN;
        ESP_LOGI(TAG, "Packet: len=%d, hdr=%d, payload=%d", packet[0], hdr_len, payload_len);
        ESP_LOG_BUFFER_HEX(TAG, packet, packet[0] + 1);
        esp_ieee802154_transmit(packet, false);

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}