#ifndef _CAPABILITIES_H_
#define _CAPABILITIES_H_

#ifdef DS18B20
    #define HAS_DS18B20 1
#else 
    #define HAS_DS18B20 0
#endif

#if defined(HLW8012_SEL) && defined(HLW8012_CF) && defined (HLW8012_CF1)
    #define HAS_HLW8012 1
#else
    #define HAS_HLW8012 0
#endif

/*
    uint8_t pin; // pin number for digitalWrite()
    uint8_t activeLow:1; // 1 when relay is closed by LOW state (0V)
    uint8_t state:1;     // desired relay state (pin = state xor activeLow) 
*/
#define RELAYSDEF { RELAYSPEC(RELAYGPIO, !RELAYONVAL, 0) }

#endif //_CAPABILITIES_H_
