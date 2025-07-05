#ifndef WIFI_H
#define WIFI_H

esp_err_t wifi_driver_init(void);
esp_err_t wifi_driver_connect(void);
esp_err_t wifi_driver_disconnect(void);
esp_err_t wifi_driver_deinit(void);


#endif