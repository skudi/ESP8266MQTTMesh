/*
 *  Copyright (C) 2016 PhracturedBlue
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  HLW8012 code Copyright (C) 2016-2017 by Xose Pérez <xose dot perez at gmail dot com>
 */
#include <Arduino.h>

/* Sonoff POW w/ DS18B20 attached to GPIO2(SDA) */
#define GREEN_LED   15 //MTDO

#ifndef STATUS_LED
#define STATUS_LED GREEN_LED
#endif

#ifndef MINHEARBEAT
#define MINHEARBEAT 2000
#endif

struct RelayStruct {
	uint8_t pin; // pin number for digitalWrite()
    uint8_t activeLow:1; // 1 when relay is closed by LOW state (0V)
    uint8_t state:1;     // desired relay state (pin = state xor activeLow) 
};
#define RELAYSPEC(pin, activeLow, state) {pin, activeLow, state}

/* See credentials.h.examle for contents of credentials.h */
#include "credentials.h"
#include "capabilities.h"
#include <ESP8266WiFi.h>
#include <FS.h>
#include <ESP8266MQTTMesh.h>

#define      FIRMWARE_VER       "0.8.2"
const wifi_conn networks[]    = NETWORK_LIST;
const char*  mesh_password    = MESH_PASSWORD;
const mqtt_conn mqtt_servers[]   = MQTT_SERVERS;

ESP8266MQTTMesh mesh = ESP8266MQTTMesh::Builder(networks, mqtt_servers)
                     .setVersion(FIRMWARE_VER, FIRMWARE_ID)
                     .setMeshPassword(mesh_password)
                     .build();


struct RelayStruct relays[] = RELAYSDEF;
#define RELAYNUM ((sizeof relays)/(sizeof (struct RelayStruct)))

bool buttonState = false; //gpio IN button state
bool stateChanged = false;
int  heartbeat  = 60000;
float temperature = 0.0;

void read_config();
void save_config();
void callback(const char *topic, const char *msg);
String build_json();

void setup() {
    pinMode(STATUS_LED, OUTPUT);
    for (uint8_t i=0; i < RELAYNUM; i++){
        pinMode(relays[i].pin, OUTPUT);
    }
    pinMode(BUTTON, INPUT);
    buttonState = digitalRead(BUTTON); //read initial switch state
    Serial.begin(115200);
    mesh.setCallback(callback);
    mesh.begin();
    //mesh.setup will initialize the filesystem
    if (SPIFFS.exists("/config")) {
        read_config();
    }
    Serial.println("config end");
    for (uint8_t i=0; i < RELAYNUM; i++){
        digitalWrite(relays[i].pin, relays[i].state ^ relays[i].activeLow);
    }
	digitalWrite(STATUS_LED, !relays[0].state);
}


void loop() {
    static unsigned long prevButtonChange = 0;
    static unsigned long lastSend = 0;
    static bool needToSend = false;
		static unsigned long blinkOffTime = 0;

    unsigned long now = millis();

		if ( blinkOffTime && (now > blinkOffTime) ) {
			//blink end
			digitalWrite(STATUS_LED, !relays[0].state);
			blinkOffTime = 0;
		}

#ifdef BISTATEBUTTON
    if (buttonState != digitalRead(BUTTON))  {
#else
    if (! digitalRead(BUTTON))  {
#endif
	    //debounce delay
        if(prevButtonChange == 0) {
		    //toggle relay state
		    buttonState = digitalRead(BUTTON);
            relays[0].state = !relays[0].state;
            stateChanged = true;
        }
        prevButtonChange = now;
    } else if (prevButtonChange && now - prevButtonChange > 50) {
        prevButtonChange = 0;
    }
    if (stateChanged) {
        digitalWrite(relays[0].pin, relays[0].state ^ relays[0].activeLow);
        digitalWrite(STATUS_LED, !relays[0].state);
        save_config();
        needToSend = true;
        stateChanged = false;
    }

    if (now - lastSend > heartbeat) {
        needToSend = true;
    }
    if (! mesh.connected()) {
        return;
    }
    if (needToSend) {
        lastSend = now;
        String data = build_json();
        mesh.publish("status", data.c_str());
        needToSend = false;
		digitalWrite(STATUS_LED, relays[0].state); //toggle LED for blinkOffTime
		blinkOffTime = now + 100;
    }   
}

void callback(const char *topic, const char *msg) {
    if (0 == strcmp(topic, "heartbeat")) {
       unsigned int hb = strtoul(msg, NULL, 10);
       if (hb > MINHEARBEAT) {
           heartbeat = hb;
           save_config();
       }
    } else if (strstr(topic, "relay") == topic) {
        //accept "relay" - relay0
        // and "relay/#" - relay#
        char * relayIdxTxt = strrchr(topic, '/' );
        uint8_t relayIdx = 0;
        if (relayIdxTxt != NULL) {
            relayIdx = atoi(relayIdxTxt+1);
        }
        if (relayIdx >= RELAYNUM) {
            relayIdx = 0;
        }
       bool nextState = strtoul(msg, NULL, 10) ? true : false;
       if (relays[relayIdx].state != nextState) {
           relays[relayIdx].state = nextState;
           digitalWrite(relays[relayIdx].pin, relays[relayIdx].state ^ relays[relayIdx].activeLow);
           stateChanged = true;
       }
    } else if (strstr(topic, "config/read") == topic) {
        read_config();
    }
}

String build_json() {
    String msg = "{ \"v\":\"1\"";
    msg += ", \"buttons\":{";
    msg += "\"0\":\"" + String(digitalRead(BUTTON) ? "1" : "0") + "\"";
    msg += "}";
    msg += ", \"relays\":{";
    for (uint8_t i=0; i < RELAYNUM; i++) {
        if (i>0) { msg+= ",";}
        msg += "\"" + String(i) + "\":\"" + (relays[i].state ? "1" : "0") + "\"";
    }
    msg += "}";
    msg += "}";
    return msg;
}

void read_config() {
    File f = SPIFFS.open("/config", "r");
    if (! f) {
        Serial.println("Failed to read config");
        return;
    }
    while(f.available()) {
        char s[32];
        char key[32];
        const char *value;
        s[f.readBytesUntil('\n', s, sizeof(s)-1)] = 0;
        if (mesh.connected()) {
            mesh.publish("config", s);
        }
        if (! ESP8266MQTTMesh::keyValue(s, '=', key, sizeof(key), &value)) {
            continue;
        }
        if (strstr(key, "RELAY") == key) {
            // RELAY or RELAY#
            uint8_t relayIdx = 0;
            if (strlen(key) > strlen("RELAY")) {
                relayIdx = atoi(key + strlen("RELAY"));
            }
            relays[relayIdx].state = value[0] == '0' ? 0 : 1;
        }
        else if (0 == strcmp(key, "HEARTBEAT")) {
            heartbeat = atoi(value);
            if (heartbeat < 1000) {
                heartbeat = 1000;
            } else if (heartbeat > 60 * 60 * 1000) {
                heartbeat = 5 * 60 * 1000;
            }
        }
    }
    f.close();
}

void save_config() {
    File f = SPIFFS.open("/config", "w");
    if (! f) {
        Serial.println("Failed to write config");
        return;
    }
    for (uint8_t i=0; i < RELAYNUM; i++) {
        f.print("RELAY" + String(i) + "=" + (relays[i].state ? "1" : "0") + "\n");
    }
    f.print("HEARTBEAT=" + String(heartbeat) + "\n");
    f.close();
}
