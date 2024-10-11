#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

#include <Arduino.h>

struct configuration {
  uint8_t version = 0;
  char8_t[50] wifiap;
  char8_t[50] wifipw;
  uint8t status_led_pin;
};

#endif //_CONFIGURATION_H_

