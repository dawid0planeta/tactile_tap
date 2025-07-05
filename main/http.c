
#include <esp_http_client.h>
#include <esp_log.h>
#include "esp_tls.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048
static const char *TAG = "HTTP_CLIENT";

typedef struct {
    char cookie_buff[512];
    bool is_set;
} cookie_t;

#define HOST_URL "http://192.168.50.7/app\0"
#define URL_SIZE 512
#define COOKIE_HEADER_SIZE 700

static esp_http_client_handle_t client= NULL;
static char response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};
static cookie_t cookie = {
    .cookie_buff = {0},
    .is_set = false,
};

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            if (strcmp(evt->header_key, "Set-Cookie") == 0)
            {
                ESP_LOGD(TAG, "Saving cookie");
                char *semicolon_ptr = strchr(evt->header_value, ';');
                size_t cookie_len = semicolon_ptr - evt->header_value;
                ESP_LOGD(TAG, "Found ';' in cookie");
                memset(cookie.cookie_buff, 0x00, sizeof(cookie.cookie_buff));
                memcpy(cookie.cookie_buff, evt->header_value, cookie_len);
                cookie.is_set = true;
                ESP_LOG_BUFFER_HEXDUMP(TAG, cookie.cookie_buff, strlen(cookie.cookie_buff), ESP_LOG_DEBUG);
            }
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Clean the buffer in case of a new request
            if (output_len == 0 && evt->user_data) {
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
            }
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                    copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                    if (copy_len) {
                        memcpy(evt->user_data + output_len, evt->data, copy_len);
                    }
                } else {
                    int content_len = esp_http_client_get_content_length(evt->client);
                    if (output_buffer == NULL) {
                        // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                        output_buffer = (char *) calloc(content_len + 1, sizeof(char));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    copy_len = MIN(evt->data_len, (content_len - output_len));
                    if (copy_len) {
                        memcpy(output_buffer + output_len, evt->data, copy_len);
                    }
                }
                output_len += copy_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
#if CONFIG_EXAMPLE_ENABLE_RESPONSE_BUFFER_DUMP
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
#endif
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGD(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGD(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
    }
    return ESP_OK;
}



void http_client_init()
{
    esp_http_client_config_t config = {
        .url = HOST_URL,
        .event_handler = _http_event_handler,
        .user_data = response_buffer,
        .disable_auto_redirect = true,
        .method = HTTP_METHOD_POST,
        .is_async = true,
    };

    ESP_LOGD(TAG, "HTTP request with url =>");

    client = esp_http_client_init(&config);
}

void http_client_post(char *path, char* data, size_t data_len, char* response)
{
    char url[URL_SIZE] = {0};
    // char *test_buff = (char *)malloc(2048 * sizeof(char));
    // memset(test_buff, 0x00, 2048);
    char *test_buff;
    snprintf(url, sizeof(url), "%s%s", HOST_URL, path);

    ESP_LOGD(TAG, "URL: %s", url);

    esp_http_client_set_url(client, url);
    ESP_LOGD(TAG, "Data before set");
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, data_len, ESP_LOG_DEBUG);
    esp_http_client_set_post_field(client, (const char *)data, data_len);
    // heap_caps_check_integrity_all(true);
    esp_http_client_get_post_field(client, &test_buff);
    ESP_LOGD(TAG, "Post field");
    ESP_LOG_BUFFER_HEXDUMP(TAG, test_buff, data_len, ESP_LOG_DEBUG);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    ESP_LOGD(TAG, "Request setup done");

    if (cookie.is_set)
    {
        esp_http_client_set_header(client, "Cookie", cookie.cookie_buff);
    }

    ESP_LOGI(TAG, "Sending request");
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Response received");
        size_t content_len = esp_http_client_get_content_length(client);
        ESP_LOGD(TAG, "HTTP POST Status = %d, content_length = %zu",
                esp_http_client_get_status_code(client), content_len);
        ESP_LOG_BUFFER_HEXDUMP(TAG, response_buffer, content_len, ESP_LOG_DEBUG);

        memcpy(response, response_buffer, content_len);

    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }
}
