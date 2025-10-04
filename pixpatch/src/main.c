#include "libefpix.h"
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#define MAX_CONTACTS 10
#define MAX_HASHES 100

Identity sender_node, relay_node, receiver_node;
uint8_t sender_stored_hashes[MAX_HASHES][HASH_SIZE], relay_stored_hashes[MAX_HASHES][HASH_SIZE], receiver_stored_hashes[MAX_HASHES][HASH_SIZE];
int sender_hash_count = 0;
int relay_hash_count = 0;
int receiver_hash_count = 0;
Contact sender_contacts[MAX_CONTACTS], relay_contacts[MAX_CONTACTS], receiver_contacts[MAX_CONTACTS];
int sender_contact_count = 0;
int relay_contact_count = 0;
int receiver_contact_count = 0;

void print_hex(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
bool sender_hash_check_and_relay(uint8_t hash[HASH_SIZE], uint8_t packet[PACKET_SIZE]) {
    for (int i = 0; i < sender_hash_count; i++) {
        if (memcmp(sender_stored_hashes[i], hash, HASH_SIZE) == 0) return false;
    }
    if (sender_hash_count < 100) {
        memcpy(sender_stored_hashes[sender_hash_count], hash, HASH_SIZE);
        sender_hash_count=sender_hash_count+1;
    }
    printf("RELAY: ");
    print_hex(packet, PACKET_SIZE);
    return true;
}
bool relay_hash_check_and_relay(uint8_t hash[HASH_SIZE], uint8_t packet[PACKET_SIZE]) {
    for (int i = 0; i < relay_hash_count; i++) {
        if (memcmp(relay_stored_hashes[i], hash, HASH_SIZE) == 0) return false;
    }
    if (relay_hash_count < 100) {
        memcpy(relay_stored_hashes[relay_hash_count], hash, HASH_SIZE);
        relay_hash_count=relay_hash_count+1;
    }
    printf("RELAY: ");
    print_hex(packet, PACKET_SIZE);
    return true;
}
bool receiver_hash_check_and_relay(uint8_t hash[HASH_SIZE], uint8_t packet[PACKET_SIZE]) {
    for (int i = 0; i < receiver_hash_count; i++) {
        if (memcmp(receiver_stored_hashes[i], hash, HASH_SIZE) == 0) return false;
    }
    if (receiver_hash_count < 100) {
        memcpy(receiver_stored_hashes[receiver_hash_count], hash, HASH_SIZE);
        receiver_hash_count=receiver_hash_count+1;
    }
    printf("RELAY: ");
    print_hex(packet, PACKET_SIZE);
    return true;
}
bool sender_get_contact_from_alias(uint8_t alias[ALIAS_SIZE], Contact* contact) {
    for (int i = 0; i < sender_contact_count; i++) {
        if (memcmp(sender_contacts[i].their_alias, alias, ALIAS_SIZE) == 0) {
            memcpy(contact, &sender_contacts[i], sizeof(Contact));
            return true;
        }
    }
    return false;
}
bool relay_get_contact_from_alias(uint8_t alias[ALIAS_SIZE], Contact* contact) {
    for (int i = 0; i < relay_contact_count; i++) {
        if (memcmp(relay_contacts[i].their_alias, alias, ALIAS_SIZE) == 0) {
            memcpy(contact, &relay_contacts[i], sizeof(Contact));
            return true;
        }
    }
    return false;
}
bool receiver_get_contact_from_alias(uint8_t alias[ALIAS_SIZE], Contact* contact) {
    for (int i = 0; i < receiver_contact_count; i++) {
        if (memcmp(receiver_contacts[i].their_alias, alias, ALIAS_SIZE) == 0) {
            memcpy(contact, &receiver_contacts[i], sizeof(Contact));
            return true;
        }
    }
    return false;
}
void get_timestamp(uint8_t timestamp[TIMESTAMP_SIZE]) {
    uint64_t now = (uint64_t)time(NULL);
    memcpy(timestamp, &now, TIMESTAMP_SIZE);
}
uint32_t get_age(uint8_t recv_time[TIMESTAMP_SIZE], uint8_t send_time[TIMESTAMP_SIZE]) {
    uint64_t recv_ts, send_ts;
    memcpy(&recv_ts, recv_time, TIMESTAMP_SIZE);
    memcpy(&send_ts, send_time, TIMESTAMP_SIZE);
    if (recv_ts >= send_ts) {
        return (uint32_t)(recv_ts - send_ts);
    } else {
        return UINT32_MAX;
    }
}

void add_contact(Contact contacts[MAX_CONTACTS], int* contact_count, const char* their_alias_str, uint8_t kx_public_key[32], uint8_t sign_public_key[32], const char* my_alias_str) {
    if (*contact_count < 10) {
        memset(contacts[*contact_count].their_alias, 0, ALIAS_SIZE);
        memset(contacts[*contact_count].my_alias, 0, ALIAS_SIZE);
        strncpy((char*)contacts[*contact_count].their_alias, their_alias_str, ALIAS_SIZE - 1);
        strncpy((char*)contacts[*contact_count].my_alias, my_alias_str, ALIAS_SIZE - 1);
        memcpy(contacts[*contact_count].kx_public_key, kx_public_key, 32);
        memcpy(contacts[*contact_count].sign_public_key, sign_public_key, 32);
        *contact_count=*contact_count+1;
    }
}
void alias_copy(uint8_t dest[ALIAS_SIZE], const char* src) {
    memset(dest, 0, ALIAS_SIZE);
    strncpy((char*)dest, src, ALIAS_SIZE - 1);
}

void dispatch_send(char* message, uint8_t packet[PACKET_SIZE]){
    Send send_msg={0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    memcpy(&send_msg.identity, &sender_node, sizeof(Identity));
    alias_copy(send_msg.my_alias, "DISPATCH");
    memcpy(send_msg.receiver_kx_public_key, receiver_node.kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "001", 3);
    strncpy((char*)send_msg.message, message, MESSAGE_SIZE - 1);
    encode(send_msg, packet);
}

bool agent_recv(uint8_t packet[PACKET_SIZE], Recv* recv){
    return decode(packet, receiver_node, recv, receiver_hash_check_and_relay, receiver_get_contact_from_alias, get_timestamp, get_age);
}

int main() {
    generate_identity(&sender_node);
    generate_identity(&relay_node);
    generate_identity(&receiver_node);

    add_contact(sender_contacts, &sender_contact_count, "AGENT", receiver_node.kx_public_key, receiver_node.sign_public_key, "DISPATCH");
    add_contact(receiver_contacts, &receiver_contact_count, "DISPATCH", sender_node.kx_public_key, sender_node.sign_public_key, "AGENT");
    
    printf("============DISPATCH================\n");
    char dispatch_message[MESSAGE_SIZE]={0};
    printf("DISPATCH: ");
    fgets(dispatch_message, MESSAGE_SIZE, stdin);
    size_t len = strlen(dispatch_message);
    if (len > 0 && dispatch_message[len-1] == '\n') {
        dispatch_message[len-1] = '\0';
    }
    uint8_t packet[PACKET_SIZE];
    dispatch_send(dispatch_message, packet);
    printf("DISPATCHING RELAYING: %s\n", dispatch_message);
    printf("PACKET: ");
    print_hex(packet, PACKET_SIZE);
    getchar();
    system("clear");

    //relay packet with any means (radio)

    //relay node gets the relayed packet
    printf("============RELAY NODE================\n");
    printf("RELAYING: ");
    print_hex(packet, PACKET_SIZE);
    getchar();
    system("clear");


    //relay packet with any means (radio)

    //agent node gets the relayed packet
    printf("============AGENT================\n");
    Recv recv_msg = {0};
    agent_recv(packet, &recv_msg);
    printf("[%s] ", recv_msg.contact.their_alias);
    printf("%s\n", recv_msg.message);

    return 0;
}