#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>

#define MAC_LENGTH 6
#define BEACON_FRAME_LENGTH 92

struct beacon_frame {
    unsigned char type;
    unsigned char flags;
    unsigned short duration;
    unsigned char dest_addr[MAC_LENGTH];
    unsigned char src_addr[MAC_LENGTH];
    unsigned char bssid[MAC_LENGTH];
    unsigned short sequence;
    unsigned char timestamp[8];
    unsigned short beacon_interval;
    unsigned short capabilities;
    unsigned char ssid_element_id;
    unsigned char ssid_length;
    unsigned char ssid_value[32];
};

void generateRandomSSID(unsigned char *ssid) {
    const char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int i;
    for (i = 0; i < 6; i++) {
        ssid[i] = characters[rand() % (sizeof(characters) - 1)];
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct beacon_frame frame;
    unsigned char ssid[32];

    srand(time(NULL));
    generateRandomSSID(ssid);

    handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "ERR on interface: %s\n", errbuf);
        return 1;
    }

    while (1) {
        memset(&frame, 0, sizeof(struct beacon_frame));
        frame.type = 0x80;
        frame.flags = 0x00;
        memcpy(frame.dest_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", MAC_LENGTH);
        memcpy(frame.src_addr, "\x00\x11\x22\x33\x44\x55", MAC_LENGTH);
        memcpy(frame.bssid, "\x00\x11\x22\x33\x44\x55", MAC_LENGTH); 
        frame.sequence = 0x00;
        memcpy(frame.timestamp, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
        frame.beacon_interval = 0x64; 
        frame.capabilities = 0x01;

        frame.ssid_element_id = 0x00;
        frame.ssid_length = strlen(ssid);
        memcpy(frame.ssid_value, ssid, strlen(ssid));

        if (pcap_inject(handle, &frame, BEACON_FRAME_LENGTH) == -1) {
            fprintf(stderr, "ERR on packet injection: %s\n", pcap_geterr(handle));
            break;
        }

        printf("Beacon frame: SSID: %s\n", ssid);

        sleep(2); 
    }

    pcap_close(handle);

    return 0;
}
