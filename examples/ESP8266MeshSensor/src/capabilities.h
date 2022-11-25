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
#define RELAYSPECn(n) RELAYSPEC(RELAY ## n ## GPIO, !RELAY ## n ## ONVAL, 0)

#ifdef RELAY7GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2), RELAYSPECn(3), RELAYSPECn(4), RELAYSPECn(5), RELAYSPECn(6), RELAYSPECn(7) }
#elif RELAY6GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2), RELAYSPECn(3), RELAYSPECn(4), RELAYSPECn(5), RELAYSPECn(6) }
#elif RELAY5GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2), RELAYSPECn(3), RELAYSPECn(4), RELAYSPECn(5) }
#elif RELAY4GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2), RELAYSPECn(3), RELAYSPECn(4) }
#elif RELAY3GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2), RELAYSPECn(3) }
#elif RELAY2GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1), RELAYSPECn(2) }
#elif RELAY1GPIO
#define RELAYSDEF { RELAYSPECn(0), RELAYSPECn(1) }
#elif RELAY0GPIO
#define RELAYSDEF { RELAYSPECn(0) }
#endif


#endif //_CAPABILITIES_H_
