#include "credentials.h"
#include <ESP8266MQTTMesh.h>
#include <FS.h>


#ifndef STATUS_LED
  #define STATUS_LED LED_BUILTIN
#endif


#define      FIRMWARE_ID        0x1337
#define      FIRMWARE_VER       "0.1"
wifi_conn    networks[]       = NETWORK_LIST;
const char*  mesh_password    = MESH_PASSWORD;
const mqtt_conn mqtt_servers[]   = MQTT_SERVERS;
#if ASYNC_TCP_SSL_ENABLED
  #if MESH_SECURE
  #include "ssl_cert.h"
  #endif
#endif

String ID  = String(getChipId());

unsigned long previousMillis = 0;
const long interval = 1000;
int cnt = 0;

// Note: All of the '.set' options below are optional.  The default values can be
// found in ESP8266MQTTMeshBuilder.h
ESP8266MQTTMesh mesh = ESP8266MQTTMesh::Builder(networks, mqtt_servers)
                       .setVersion(FIRMWARE_VER, FIRMWARE_ID)
                       .setMeshPassword(mesh_password)
#if ASYNC_TCP_SSL_ENABLED
#if MESH_SECURE
                       .setMeshSSL(ssl_cert, ssl_cert_len, ssl_key, ssl_key_len, ssl_fingerprint)
#endif //MESH_SECURE
#endif //ASYNC_TCP_SSL_ENABLED
                       .build();

void callback(const char *topic, const char *msg);



void setup() {
    Serial.begin(115200);
    mesh.setCallback(callback);
    mesh.begin();
    pinMode(STATUS_LED, OUTPUT);
		Serial.println("setup end");
}


void loop() {
    unsigned long currentMillis = millis();

    if (currentMillis - previousMillis >= interval) {
			Serial.println(".");
			if (mesh.connected()) {
				String cntStr = String(cnt);
				String msg = "hello from " + ID + " cnt: " + cntStr;
				mesh.publish(ID.c_str(), msg.c_str());
				cnt++;
			}
			if (!WiFi.isConnected()) {
				ap_t* activeAP = mesh.getActiveAP();
				if (activeAP != NULL) {
					Serial.print("activeAP: ");
					Serial.println(mesh.getActiveAPssid());
#ifdef ESP32
					WiFi.begin(mesh.getActiveAPssid().c_str(), mesh.getActiveAPpassword().c_str());
#endif
				}
			}
			previousMillis = currentMillis;
    }

}



void callback(const char *topic, const char *msg) {


    if (0 == strcmp(topic, (const char*) ID.c_str())) {
      if(String(msg) == "0") {
        digitalWrite(STATUS_LED, HIGH);
      }else{
        digitalWrite(STATUS_LED, LOW);
      }
    }
}
