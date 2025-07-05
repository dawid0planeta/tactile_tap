#ifndef ADC_H
#define ADC_H

void adc_task(void *pvParameters);
uint16_t adc_get_brightness();
uint32_t adc_get_temp();

#endif