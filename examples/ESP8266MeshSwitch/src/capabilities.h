#ifndef _CAPABILITIES_H_
#define _CAPABILITIES_H_

/*
    uint8_t pin; // pin number for digitalWrite()
    uint8_t activeLow:1; // 1 when relay is closed by LOW state (0V)
    uint8_t state:1;     // desired relay state (pin = state xor activeLow) 
*/
#define RELAYSPECn(n) RELAYSPEC(RELAY ## n ## GPIO, !RELAY ## n ## ONVAL, 0)

#ifdef RELAY0GPIO
#define RELAYSDEF { RELAYSPECn(0) }
#endif


#endif //_CAPABILITIES_H_
