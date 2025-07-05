/* Blink Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "driver/gpio.h"

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"

#include "wifi.h"
#include "adc.h"
#include "tapo_cipher.h"
#include "tapo_protocol.h"

static const char *TAG = "main";


void app_main(void)
{
    ESP_ERROR_CHECK(wifi_driver_init());

    esp_err_t ret = wifi_driver_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi network");
    }

    wifi_ap_record_t ap_info;
    ret = esp_wifi_sta_get_ap_info(&ap_info);
    if (ret == ESP_ERR_WIFI_CONN) {
        ESP_LOGE(TAG, "Wi-Fi station interface not initialized");
    }
    else if (ret == ESP_ERR_WIFI_NOT_CONNECT) {
        ESP_LOGE(TAG, "Wi-Fi station is not connected");
    } else {
        ESP_LOGI(TAG, "--- Access Point Information ---");
        ESP_LOG_BUFFER_HEX("MAC Address", ap_info.bssid, sizeof(ap_info.bssid));
        ESP_LOG_BUFFER_CHAR("SSID", ap_info.ssid, sizeof(ap_info.ssid));
        ESP_LOGI(TAG, "Primary Channel: %d", ap_info.primary);
        ESP_LOGI(TAG, "RSSI: %d", ap_info.rssi);
    }

    xTaskCreate(adc_task, "adc_task", 16096, NULL, 5, NULL);

    tapo_protocol_handshake();

    char cmd_buffer[256] = {0};
    uint16_t prev_brightness = 0;
    uint32_t prev_temp = 0;

    while (1) {
        if ((esp_timer_get_time() / 1000000) % 3600 == 0)
        {
            tapo_protocol_handshake();
        }
        memset(cmd_buffer, 0x00, 256);
        uint16_t brightness = adc_get_brightness();
        uint32_t temp = adc_get_temp();
        if (abs((int32_t)brightness - (int32_t)prev_brightness) > 4 || (brightness == 0 && prev_brightness != 0))
        { 
            if (brightness == 0)
            {
                tapo_protocol_send("{\"method\":\"set_device_info\", \"params\":{\"device_on\":false}}");
            }
            else
            {
                snprintf(cmd_buffer, 256, "{\"method\":\"set_device_info\", \"params\":{\"brightness\":%u}}", brightness);
                tapo_protocol_send(cmd_buffer);
            }
            prev_brightness = brightness;
            // vTaskDelay(100 / portTICK_PERIOD_MS);
        }
        else if (abs((int32_t)temp - (int32_t)prev_temp) > 50)
        { 
            snprintf(cmd_buffer, 256, "{\"method\":\"set_device_info\", \"params\":{\"color_temp\":%lu}}", temp);
            tapo_protocol_send(cmd_buffer);
            prev_temp = temp;
        }
        else
        {
            vTaskDelay(20 / portTICK_PERIOD_MS);
        }
    }
}
