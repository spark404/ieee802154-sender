#include <string.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_ieee802154.h>
#include <esp_log.h>
#include <esp_phy_init.h>
#include <esp_mac.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "ieee802154.h"

#define TAG "main"
#define RADIO_TAG "ieee802154"

#define PAN_BROADCAST 0xFFFF
#define PANID 0x4242
#define CHANNEL 19

#define SHORT_BROADCAST 0xFFFF
#define SHORT_NOT_CONFIGURED 0xFFFE
#define SHORT_TEST_SENDER 0x1111
#define SHORT_TEST_RECEIVER 0x2222


void esp_ieee802154_receive_done(uint8_t* frame, esp_ieee802154_frame_info_t* frame_info) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx OK, received %d bytes", frame[0]);
}

void esp_ieee802154_receive_failed(uint16_t error) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx failed, error %d", error);
}

void esp_ieee802154_receive_sfd_done(void) {
    ESP_EARLY_LOGI(RADIO_TAG, "rx sfd done, Radio state: %d", esp_ieee802154_get_state());
}
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_frame_info) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx OK, sent %d bytes, ack %d", frame[0], ack != NULL);
}

void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx failed, error %d", error);
}

void esp_ieee802154_transmit_sfd_done(uint8_t *frame) {
    ESP_EARLY_LOGI(RADIO_TAG, "tx sfd done");
}

void send_broadcast(uint16_t pan_id);
void send_direct_long(uint16_t pan_id, uint8_t dst_long[8], bool ack);
void send_direct_short(uint16_t pan_id, uint16_t dst_short, bool ack);

void app_main() {
    ESP_LOGI(TAG, "Initializing NVS from flash...");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_coordinator(false));
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));

    ESP_ERROR_CHECK(esp_ieee802154_set_panid(PANID));
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(CHANNEL));

    uint8_t eui64[8] = {0};
    esp_read_mac(eui64, ESP_MAC_IEEE802154);
    esp_ieee802154_set_extended_address(eui64);
    esp_ieee802154_set_short_address(SHORT_TEST_SENDER);

    ESP_ERROR_CHECK(esp_ieee802154_receive());

    uint8_t extended_address[8];
    esp_ieee802154_get_extended_address(extended_address);
    ESP_LOGI(TAG, "Ready, panId=0x%04x, channel=%d, long=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, short=%04x",
             esp_ieee802154_get_panid(), esp_ieee802154_get_channel(),
             extended_address[0], extended_address[1], extended_address[2], extended_address[3],
             extended_address[4], extended_address[5], extended_address[6], extended_address[7],
             esp_ieee802154_get_short_address());

    // This device should try to communicate with the
    // ieee802154-receiver app. It will send a sequence of packets using various
    // addressing methods to see what works.
    uint8_t peer[8] = { 0x40, 0x4c, 0xca, 0x40, 0x28, 0xdc, 0xfe, 0xff};
    uint16_t peer_short = 0x2222;
    while (true) {
        send_broadcast(PANID);

        vTaskDelay(pdMS_TO_TICKS(5000));

        send_direct_long(PANID, peer, false);

        vTaskDelay(pdMS_TO_TICKS(5000));

        send_direct_short(PANID, peer_short, false);

        vTaskDelay(pdMS_TO_TICKS(5000));

        send_direct_long(PANID, peer, true);

        vTaskDelay(pdMS_TO_TICKS(5000));

        send_direct_short(PANID, peer_short, true);

        vTaskDelay(pdMS_TO_TICKS(20000));
    }
}

void send_broadcast(uint16_t pan_id) {
    ESP_LOGI(TAG, "Send broadcast from pan %04x", pan_id);
    uint8_t buffer[256];

    esp_ieee802154_set_panid(pan_id);

    uint8_t eui64[8];
    esp_ieee802154_get_extended_address(eui64);

    ieee802154_address_t src = {
            .mode = ADDR_MODE_LONG,
            .long_address = { eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7]}
    };

    ieee802154_address_t dst = {
        .mode = ADDR_MODE_SHORT,
        .short_address = SHORT_BROADCAST
    };

    uint16_t dst_pan = PAN_BROADCAST;

    uint8_t hdr_len = ieee802154_header(&pan_id, &src, &dst_pan, &dst, false, &buffer[1], sizeof(buffer) - 1);

    // Add the local eui64 as payload
    memcpy(&buffer[1 + hdr_len], eui64, 8);

    // packet length
    buffer[0] = hdr_len + 8;

    esp_ieee802154_transmit(buffer, false);
}

void send_direct_long(uint16_t pan_id, uint8_t dst_long[8], bool ack) {
    ESP_LOGI(TAG, "Send direct message to %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x on pan %04x%s",
             dst_long[0], dst_long[1], dst_long[2], dst_long[3], dst_long[4], dst_long[5], dst_long[6], dst_long[7],
             pan_id, ack ? " with ack" : "");
    uint8_t buffer[256];

    esp_ieee802154_set_panid(pan_id);

    uint8_t eui64[8];
    esp_ieee802154_get_extended_address(eui64);

    ieee802154_address_t src = {
            .mode = ADDR_MODE_LONG,
            .long_address = { eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7]}
    };

    ieee802154_address_t dst = {
            .mode = ADDR_MODE_LONG,
            .long_address = { dst_long[0], dst_long[1], dst_long[2], dst_long[3], dst_long[4], dst_long[5], dst_long[6], dst_long[7]}
    };

    uint16_t dst_pan = PANID;

    uint8_t hdr_len = ieee802154_header(&pan_id, &src, &dst_pan, &dst, ack, &buffer[1], sizeof(buffer) - 1);

    // Add the local eui64 as payload
    memcpy(&buffer[1 + hdr_len], eui64, 8);

    // packet length
    buffer[0] = hdr_len + 8;

    esp_ieee802154_transmit(buffer, false);
}

void send_direct_short(uint16_t pan_id, uint16_t dst_short, bool ack) {
    ESP_LOGI(TAG, "Send direct message to %04x on pan %04x%s", dst_short, pan_id, ack ? " with ack" : "");
    uint8_t buffer[256];

    esp_ieee802154_set_panid(pan_id);

    uint8_t eui64[8];
    esp_ieee802154_get_extended_address(eui64);

    ieee802154_address_t src = {
            .mode = ADDR_MODE_LONG,
            .long_address = { eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7]}
    };

    ieee802154_address_t dst = {
            .mode = ADDR_MODE_SHORT,
            .short_address = dst_short
    };

    uint16_t dst_pan = PANID;

    uint8_t hdr_len = ieee802154_header(&pan_id, &src, &dst_pan, &dst, ack, &buffer[1], sizeof(buffer) - 1);

    // Add the local eui64 as payload
    memcpy(&buffer[1 + hdr_len], eui64, 8);

    // packet length
    buffer[0] = hdr_len + 8;

    esp_ieee802154_transmit(buffer, false);
}