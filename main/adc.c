
#include <string.h>
#include <stdio.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_adc/adc_continuous.h"

#include "adc.h"

#define ADC_UNIT                    ADC_UNIT_1
#define ADC_CONV_MODE               ADC_CONV_SINGLE_UNIT_1
#define ADC_ATTEN                   ADC_ATTEN_DB_6
#define ADC_BIT_WIDTH               SOC_ADC_DIGI_MAX_BITWIDTH

#define ADC_OUTPUT_TYPE             ADC_DIGI_OUTPUT_FORMAT_TYPE2
#define ADC_GET_CHANNEL(p_data)     ((p_data)->type2.channel)
#define ADC_GET_DATA(p_data)        ((uint16_t)(p_data)->type2.data)

#define ADC_CONV_NUM                250
#define ADC_SAMPLES_PER_CONV        10
#define ADC_CHANNEL_NUM             2
#define ADC_SAMPLE_SIZE             SOC_ADC_DIGI_RESULT_BYTES * ADC_CHANNEL_NUM
#define ADC_READ_LEN                (ADC_SAMPLE_SIZE * ADC_SAMPLES_PER_CONV)


static adc_channel_t channel[ADC_CHANNEL_NUM] = {ADC_CHANNEL_0, ADC_CHANNEL_1};

static TaskHandle_t s_task_handle;
static const char *TAG = "adc";
uint16_t ch0_avg = 0;
uint16_t ch1_avg = 0;


static bool IRAM_ATTR s_conv_done_cb(adc_continuous_handle_t handle, const adc_continuous_evt_data_t *edata, void *user_data)
{
    BaseType_t mustYield = pdFALSE;
    //Notify that ADC continuous driver has done enough number of conversions
    vTaskNotifyGiveFromISR(s_task_handle, &mustYield);

    return (mustYield == pdTRUE);
}

static void adc_init(adc_channel_t *channel, uint8_t channel_num, adc_continuous_handle_t *out_handle)
{
    adc_continuous_handle_t handle = NULL;

    adc_continuous_handle_cfg_t adc_config = {
        .max_store_buf_size = ADC_READ_LEN * 4,
        .conv_frame_size = ADC_READ_LEN,
        .flags.flush_pool = 1,
    };
    ESP_ERROR_CHECK(adc_continuous_new_handle(&adc_config, &handle));

    adc_continuous_config_t dig_cfg = {
        .sample_freq_hz = 50 * 1000, // at 10kHz, 100 samples per conv -> conv callback every 10ms
        .conv_mode = ADC_CONV_MODE,
        .format = ADC_OUTPUT_TYPE,
    };

    adc_digi_pattern_config_t adc_pattern[SOC_ADC_PATT_LEN_MAX] = {0};
    dig_cfg.pattern_num = channel_num;
    for (int i = 0; i < channel_num; i++) {
        adc_pattern[i].atten = ADC_ATTEN;
        adc_pattern[i].channel = channel[i] & 0x7;
        adc_pattern[i].unit = ADC_UNIT;
        adc_pattern[i].bit_width = ADC_BIT_WIDTH;

        ESP_LOGI(TAG, "adc_pattern[%d].atten is :%"PRIx8, i, adc_pattern[i].atten);
        ESP_LOGI(TAG, "adc_pattern[%d].channel is :%"PRIx8, i, adc_pattern[i].channel);
        ESP_LOGI(TAG, "adc_pattern[%d].unit is :%"PRIx8, i, adc_pattern[i].unit);
    }
    dig_cfg.adc_pattern = adc_pattern;
    ESP_ERROR_CHECK(adc_continuous_config(handle, &dig_cfg));
    *out_handle = handle;
}

void adc_task(void *pvParameters)
{
    ESP_LOGI(TAG, "ADC continuous mode task init");
    esp_err_t ret;
    uint32_t ret_num = 0;
    uint8_t result[ADC_READ_LEN] = {0};
    memset(result, 0xcc, ADC_READ_LEN);

    s_task_handle = xTaskGetCurrentTaskHandle();

    adc_continuous_handle_t handle = NULL;
    ESP_LOGI(TAG, "ADC continuous mode init2");
    adc_init(channel, sizeof(channel) / sizeof(adc_channel_t), &handle);

    adc_continuous_evt_cbs_t cbs = {
        .on_conv_done = s_conv_done_cb,
    };
    ESP_ERROR_CHECK(adc_continuous_register_event_callbacks(handle, &cbs, NULL));
    ESP_ERROR_CHECK(adc_continuous_start(handle));

    uint32_t ch0_sum = 0;
    uint32_t ch1_sum = 0;
    size_t conv_no = 0;

    while (1) {

        ESP_LOGI(TAG, "ADC continuous mode init3");
        /**
         * This is to show you the way to use the ADC continuous mode driver event callback.
         * This `ulTaskNotifyTake` will block when the data processing in the task is fast.
         * However in this example, the data processing (print) is slow, so you barely block here.
         *
         * Without using this event callback (to notify this task), you can still just call
         * `adc_continuous_read()` here in a loop, with/without a certain block timeout.
         */


        while (1) {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            memset(result, 0xcc, ADC_READ_LEN);
            ret = adc_continuous_read(handle, result, ADC_READ_LEN, &ret_num, 0);
            if (ret == ESP_OK)
            {
                for (size_t sample_no = 0; sample_no < ADC_SAMPLES_PER_CONV; sample_no++)
                {
                    ch0_sum += ADC_GET_DATA((adc_digi_output_data_t*)&result[sample_no * ADC_SAMPLE_SIZE]);
                    ch1_sum += ADC_GET_DATA((adc_digi_output_data_t*)&result[sample_no * ADC_SAMPLE_SIZE + SOC_ADC_DIGI_RESULT_BYTES]);
                }

                conv_no += 1;

                if (conv_no == ADC_CONV_NUM - 1)
                {
                    ch0_avg = ch0_sum / (ADC_SAMPLES_PER_CONV * ADC_CONV_NUM);
                    ch1_avg = ch1_sum / (ADC_SAMPLES_PER_CONV * ADC_CONV_NUM);
                    ESP_LOGD(TAG, "ch0: %4u, ch1: %4u", ch0_avg, ch1_avg);
                    ch0_sum = 0;
                    ch1_sum = 0;
                    conv_no = 0;
                    // vTaskDelay(500 / portTICK_PERIOD_MS);
                }
            } else if (ret == ESP_ERR_TIMEOUT) {
                //We try to read `ADC_READ_LEN` until API returns timeout, which means there's no available data
                ESP_LOGI(TAG, "No data available");
            }
        }
    }

    ESP_ERROR_CHECK(adc_continuous_stop(handle));
    ESP_ERROR_CHECK(adc_continuous_deinit(handle));
}

uint16_t adc_get_brightness()
{
    return (uint16_t)((double)ch1_avg / 37.0);
}

uint32_t adc_get_temp()
{
    uint32_t scaled = (uint32_t)((((double)ch0_avg - 35.0)/3659.0) * 4000.0 + 2500.0);
    if (scaled < 2550)
    {
        return 2500;
    }
    else if (scaled > 6450)
    {
        return 6500;
    }
    else
    {
        return scaled;
    }
}