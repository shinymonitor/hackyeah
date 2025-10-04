#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "../lib/monocypher.h"
#include "../lib/monocypher-ed25519.h"
//=========================CONFIG==============================
#define VERSION 1
#define ALIAS_SIZE 16
#define TIMESTAMP_SIZE 8
#define INTERNAL_ADDRESS_SIZE 4
#define MESSAGE_SIZE 256
#define HASH_SIZE 64
#define POW_NONCE_SIZE 8
#define POW_ZEROS 2
#define MAX_AGE 5
//=====================HELPER PREPROCS=========================
#define UNICAST 0
#define SIGNED_BROADCAST 1
#define ANON_BROADCAST 2
#define PAYLOAD_SIZE (ALIAS_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE+MESSAGE_SIZE)
#define ENCRYPT_SIZE (PAYLOAD_SIZE+64)
#define PACKAGE_SIZE (ENCRYPT_SIZE+32+24+16)
#define BROADCAST_MESSAGE_SIZE (PACKAGE_SIZE-TIMESTAMP_SIZE-INTERNAL_ADDRESS_SIZE-64-32)
#define PACKET_SIZE  (HASH_SIZE+PACKAGE_SIZE+POW_NONCE_SIZE+1+1)
//==========================TYPES===============================
typedef struct {
    uint8_t kx_public_key[32],
    kx_secret_key[32],
    sign_public_key[32],
    sign_secret_key[64];
} Identity;
typedef struct {
    bool anonymous, broadcast;
    Identity identity; uint8_t my_alias[ALIAS_SIZE],
    receiver_kx_public_key[32],
    timestamp[TIMESTAMP_SIZE],
    internal_address[INTERNAL_ADDRESS_SIZE],
    message[MESSAGE_SIZE], broadcast_message[BROADCAST_MESSAGE_SIZE];
} Send;
typedef struct {
    uint8_t their_alias[ALIAS_SIZE],
    kx_public_key[32],
    sign_public_key[32],
    my_alias[ALIAS_SIZE];
} Contact;
typedef struct {
    bool unknown, broadcast;
    Contact contact;
    uint8_t send_timestamp[TIMESTAMP_SIZE],
    recv_timestamp[TIMESTAMP_SIZE],
    internal_address[INTERNAL_ADDRESS_SIZE],
    message[MESSAGE_SIZE], broadcast_message[BROADCAST_MESSAGE_SIZE];
} Recv;
//====================USER VISIBLE FUNCTIONS====================
void generate_identity(Identity* identity);
void encode(Send send, uint8_t packet[PACKET_SIZE]);
bool decode(uint8_t packet[PACKET_SIZE], Identity identity, Recv* recv,
    bool (*hash_check_and_relay)(uint8_t[HASH_SIZE], uint8_t[PACKET_SIZE]),
    bool (*get_contact_from_alias)(uint8_t[ALIAS_SIZE], Contact*),
    void (*get_timestamp)(uint8_t[TIMESTAMP_SIZE]),
    uint32_t (*get_age)(uint8_t[TIMESTAMP_SIZE], uint8_t[TIMESTAMP_SIZE]));
//=============================PRNG============================
#include <sys/syscall.h>
#include <unistd.h>
static inline void get_random_bytes(uint8_t* buffer, size_t len) {
    syscall(SYS_getrandom, buffer, len, 0);
}
//=============================================================
static inline bool verify_pow(uint8_t hash[HASH_SIZE]){
    for (size_t i=0; i<POW_ZEROS; ++i) if (hash[i]!=0) return false;
    return true;
}
void generate_identity(Identity* identity) {
    uint8_t seed[32];
    get_random_bytes(seed, 32);
    crypto_ed25519_key_pair(identity->sign_secret_key, identity->sign_public_key, seed);
    crypto_wipe(seed, 32);
    get_random_bytes(identity->kx_secret_key, 32);
    crypto_x25519_public_key(identity->kx_public_key, identity->kx_secret_key);
}
void encode(Send send, uint8_t packet[PACKET_SIZE]){
    uint8_t to_encrypt[ENCRYPT_SIZE]={0};
    uint8_t ephemeral_pk[32], ephemeral_sk[32], shared_secret[32];
    uint8_t mac[16], nonce[24], cipher[ENCRYPT_SIZE];
    uint8_t pow_hash[HASH_SIZE];
    memset(packet, VERSION, 1);
    if (!send.broadcast){
        if (send.anonymous) {memset(send.my_alias, 0, ALIAS_SIZE);}
        memcpy(to_encrypt, send.my_alias, ALIAS_SIZE);
        memcpy(to_encrypt+ALIAS_SIZE, send.timestamp, TIMESTAMP_SIZE);
        memcpy(to_encrypt+ALIAS_SIZE+TIMESTAMP_SIZE, send.internal_address, INTERNAL_ADDRESS_SIZE);
        memcpy(to_encrypt+ALIAS_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE, send.message, MESSAGE_SIZE);
        if (!send.anonymous) crypto_eddsa_sign(to_encrypt + PAYLOAD_SIZE, send.identity.sign_secret_key, to_encrypt, PAYLOAD_SIZE);
        get_random_bytes(ephemeral_sk, 32);
        crypto_x25519_public_key(ephemeral_pk, ephemeral_sk);
        crypto_x25519(shared_secret, ephemeral_sk, send.receiver_kx_public_key);
        get_random_bytes(nonce, 24);
        crypto_aead_lock(cipher, mac, shared_secret, nonce, NULL, 0, to_encrypt, ENCRYPT_SIZE);
        memset(packet+1, UNICAST, 1);
        memcpy(packet+1+1+HASH_SIZE, mac, 16);
        memcpy(packet+1+1+HASH_SIZE+16, nonce, 24);
        memcpy(packet+1+1+HASH_SIZE+16+24, ephemeral_pk, 32);
        memcpy(packet+1+1+HASH_SIZE+16+24+32, cipher, ENCRYPT_SIZE);
        crypto_wipe(ephemeral_sk, 32);
        crypto_wipe(shared_secret, 32);
        crypto_wipe(to_encrypt, ENCRYPT_SIZE);
    }
    else {
        if (send.anonymous) memset(packet+1, ANON_BROADCAST, 1);
        else memset(packet+1, SIGNED_BROADCAST, 1);
        if (!send.anonymous) memcpy(packet+1+1+HASH_SIZE, send.identity.sign_public_key, 32);
        memcpy(packet+1+1+HASH_SIZE+32, send.timestamp, TIMESTAMP_SIZE);
        memcpy(packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE, send.internal_address, INTERNAL_ADDRESS_SIZE);
        memcpy(packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE, send.broadcast_message, BROADCAST_MESSAGE_SIZE);
        if (!send.anonymous) crypto_eddsa_sign(packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE+BROADCAST_MESSAGE_SIZE, send.identity.sign_secret_key, packet+1+1+HASH_SIZE+32, BROADCAST_MESSAGE_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE);
    }
    crypto_blake2b(packet+1+1, HASH_SIZE, packet+1+1+HASH_SIZE, PACKAGE_SIZE);
    crypto_blake2b(pow_hash, HASH_SIZE, packet+1+1+HASH_SIZE, PACKAGE_SIZE+POW_NONCE_SIZE);
    while(!verify_pow(pow_hash)){
        get_random_bytes(packet+1+1+HASH_SIZE+PACKAGE_SIZE, POW_NONCE_SIZE);
        crypto_blake2b(pow_hash, HASH_SIZE, packet+1+1+HASH_SIZE, PACKAGE_SIZE+POW_NONCE_SIZE);
    }
}
bool decode(uint8_t packet[PACKET_SIZE], Identity identity, Recv* recv,
    bool (*hash_check_and_relay)(uint8_t[HASH_SIZE], uint8_t[PACKET_SIZE]),
    bool (*get_contact_from_alias)(uint8_t[ALIAS_SIZE], Contact*),
    void (*get_timestamp)(uint8_t[TIMESTAMP_SIZE]),
    uint32_t (*get_age)(uint8_t[TIMESTAMP_SIZE], uint8_t[TIMESTAMP_SIZE])
    ){

    uint8_t hash[HASH_SIZE], pow_hash[HASH_SIZE], check_hash[HASH_SIZE];
    uint8_t version, type;
    uint8_t mac[16], nonce[24], ephemeral_pk[32], shared_secret[32], cipher[ENCRYPT_SIZE], from_decrypt[ENCRYPT_SIZE];
    uint8_t their_alias[ALIAS_SIZE];
    static uint8_t anon_alias[ALIAS_SIZE]={0};
    uint8_t signature[64];

    memcpy(hash, packet+1+1, HASH_SIZE);
    crypto_blake2b(pow_hash, HASH_SIZE, packet+1+1+HASH_SIZE, PACKAGE_SIZE+POW_NONCE_SIZE);
    crypto_blake2b(check_hash, HASH_SIZE, packet+1+1+HASH_SIZE, PACKAGE_SIZE);
    if (!verify_pow(pow_hash) || memcmp(hash, check_hash, HASH_SIZE)!=0) return false;
    if (!hash_check_and_relay(hash, packet)) return false;
    get_timestamp(recv->recv_timestamp);
    memcpy(&version, packet, 1);
    memcpy(&type, packet+1, 1);
    if (type==UNICAST){
        memcpy(mac, packet+1+1+HASH_SIZE, 16);
        memcpy(nonce, packet+1+1+HASH_SIZE+16, 24);
        memcpy(ephemeral_pk, packet+1+1+HASH_SIZE+16+24, 32);
        memcpy(cipher, packet+1+1+HASH_SIZE+16+24+32, ENCRYPT_SIZE);
        crypto_x25519(shared_secret, identity.kx_secret_key, ephemeral_pk);
        if (crypto_aead_unlock(from_decrypt, mac, shared_secret, nonce, NULL, 0, cipher, ENCRYPT_SIZE)!=0) return false;
        memcpy(their_alias, from_decrypt, ALIAS_SIZE);
        memcpy(recv->send_timestamp, from_decrypt+ALIAS_SIZE, TIMESTAMP_SIZE);
        if (get_age(recv->recv_timestamp, recv->send_timestamp)>MAX_AGE) return false;
        memcpy(recv->internal_address, from_decrypt+ALIAS_SIZE+TIMESTAMP_SIZE, INTERNAL_ADDRESS_SIZE);
        memcpy(recv->message, from_decrypt+ALIAS_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE, MESSAGE_SIZE);
        if (memcmp(their_alias, anon_alias, ALIAS_SIZE)==0 || !get_contact_from_alias(their_alias, &(recv->contact))) {
            recv->unknown=true;
            return true;
        }
        memcpy(signature, from_decrypt+ALIAS_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE+MESSAGE_SIZE, 64);
        if (!crypto_eddsa_check(signature, recv->contact.sign_public_key, from_decrypt, PAYLOAD_SIZE)) return false;
        recv->unknown=false;
        return true;
    }
    else{
        recv->broadcast=true;
        memcpy(recv->send_timestamp, packet+1+1+HASH_SIZE+32, TIMESTAMP_SIZE);
        memcpy(recv->internal_address, packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE, INTERNAL_ADDRESS_SIZE);
        memcpy(recv->broadcast_message, packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE, BROADCAST_MESSAGE_SIZE);
        if(type==SIGNED_BROADCAST){
            memcpy(recv->contact.sign_public_key, packet+1+1+HASH_SIZE, 32);
            memcpy(signature, packet+1+1+HASH_SIZE+32+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE+MESSAGE_SIZE, 64);
            if (!crypto_eddsa_check(signature, recv->contact.sign_public_key, packet+1+1+HASH_SIZE+32, BROADCAST_MESSAGE_SIZE+TIMESTAMP_SIZE+INTERNAL_ADDRESS_SIZE)) return false;
            recv->unknown=false;
        }
        else{recv->unknown=true;}
        return true;
    }
}
