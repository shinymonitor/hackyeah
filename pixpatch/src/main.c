#include "libefpix.h"
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h> 
#include <stdlib.h>
#include <sys/ioctl.h>
//=============================================================================================
#define MAX_CONTACTS 10
#define MAX_HASHES 100
#define MAX_LINES 1000
#define MAX_COLS 1000
//=============================================================================================
Identity sender_node, relay_node, receiver_node;
uint8_t sender_stored_hashes[MAX_HASHES][HASH_SIZE], relay_stored_hashes[MAX_HASHES][HASH_SIZE], receiver_stored_hashes[MAX_HASHES][HASH_SIZE];
int sender_hash_count = 0;
int relay_hash_count = 0;
int receiver_hash_count = 0;
Contact sender_contacts[MAX_CONTACTS], relay_contacts[MAX_CONTACTS], receiver_contacts[MAX_CONTACTS];
int sender_contact_count = 0;
int relay_contact_count = 0;
int receiver_contact_count = 0;

int ignore;
//=============================================================================================
bool sender_hash_check_and_relay(uint8_t hash[HASH_SIZE], uint8_t packet[PACKET_SIZE]) {
    for (int i = 0; i < sender_hash_count; i++) {
        if (memcmp(sender_stored_hashes[i], hash, HASH_SIZE) == 0) return false;
    }
    if (sender_hash_count < 100) {
        memcpy(sender_stored_hashes[sender_hash_count], hash, HASH_SIZE);
        sender_hash_count=sender_hash_count+1;
    }
    ignore=packet[0];
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
    ignore=packet[0];
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
    ignore=packet[0];
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

void agent_send(char* message, uint8_t packet[PACKET_SIZE]){
    Send send_msg={0};
    send_msg.anonymous = false;
    send_msg.broadcast = false;
    memcpy(&send_msg.identity, &receiver_node, sizeof(Identity));
    alias_copy(send_msg.my_alias, "AGENT");
    memcpy(send_msg.receiver_kx_public_key, sender_node.kx_public_key, 32);
    get_timestamp(send_msg.timestamp);
    memcpy(send_msg.internal_address, "001", 3);
    strncpy((char*)send_msg.message, message, MESSAGE_SIZE - 1);
    encode(send_msg, packet);
}

bool dispatch_recv(uint8_t packet[PACKET_SIZE], Recv* recv){
    return decode(packet, sender_node, recv, sender_hash_check_and_relay, sender_get_contact_from_alias, get_timestamp, get_age);
}

bool agent_recv(uint8_t packet[PACKET_SIZE], Recv* recv){
    return decode(packet, receiver_node, recv, receiver_hash_check_and_relay, receiver_get_contact_from_alias, get_timestamp, get_age);
}
//=============================================================================================
#define LEAF_FG "32"
#define LEAF_BG "42"
#define GREEN_FG "92"
#define GREEN_BG "102"
#define BLACK_FG "30"
#define BLACK_BG "40"

typedef enum {
    KEY_NONE,
    KEY_CHAR, KEY_ENTER, KEY_BACKSPACE,
    KEY_ARROW_LEFT, KEY_ARROW_RIGHT,
    KEY_CTRL_Q,
} Key;
typedef struct {Key key; char ch;} KeyEvent;

size_t screen_width, screen_height;

static inline void update_screen_dimensions(){
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    screen_height=(size_t)w.ws_row-2;
    screen_width=(size_t)w.ws_col;
}

static inline char getch() {
    static struct termios oldt, newt;
    static int initialized = 0;
    if (!initialized) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO | ISIG);
        newt.c_iflag &= ~(IXON | IXOFF);
        initialized = 1;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    char ch;
    ignore=read(STDIN_FILENO, &ch, 1);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
KeyEvent get_key() {
    KeyEvent ev = { .key = KEY_NONE, .ch = 0 };
    int c = getch();
    switch (c) {
        case 17: ev.key = KEY_CTRL_Q; break;
        case 10: ev.key = KEY_ENTER; break;
        case 127: ev.key = KEY_BACKSPACE; break;
        case 27: {
            int c2 = getch();
            if (c2 == 91) {
                int c3 = getch();
                if (!((c3 >= '0') && (c3 <= '9'))) {
                    switch (c3) {
                        case 67: ev.key = KEY_ARROW_RIGHT; break;
                        case 68: ev.key = KEY_ARROW_LEFT; break;
                    }
                }
            }
        } break;
        default:
            ev.key = KEY_CHAR;
            ev.ch = c;
            break;
    }
    return ev;
}

typedef enum {DISPATCH, RELAY, AGENT} NodeType;

char* title;

void draw(NodeType node_type, char* text){
    update_screen_dimensions();
    printf("\x1b[2J\x1b[H");
    printf("\x1b["LEAF_FG";"BLACK_BG"m");
    printf("PIXPATCH v0.1.0 - Resilient Dispatch System");
    for (size_t i=0; i<(screen_width)-strlen("PIXPATCH v0.1.0 - Resilient Dispatch System"); ++i) printf("%c", ' ');
    printf("\n");
    printf("\x1b["BLACK_FG";"LEAF_BG"m");
    if (node_type==DISPATCH) title="DISPATCH";
    else if (node_type==RELAY) title="RELAY";
    else title="AGENT";
    for (size_t i=0; i<(screen_width/2)-(strlen(title)/2); ++i) printf("%c", ' ');
    printf("%s", title);
    for (size_t i=0; i<(screen_width/2)-(strlen(title)/2); ++i) printf("%c", ' ');
    printf("\n");
    printf("\x1b["LEAF_FG";"BLACK_BG"m");
    printf("%s", text);
    printf("\x1B[0m\n");
}

//=============================================================================================
int main() {
    generate_identity(&sender_node);
    generate_identity(&relay_node);
    generate_identity(&receiver_node);

    add_contact(sender_contacts, &sender_contact_count, "AGENT", receiver_node.kx_public_key, receiver_node.sign_public_key, "DISPATCH");
    add_contact(receiver_contacts, &receiver_contact_count, "DISPATCH", sender_node.kx_public_key, sender_node.sign_public_key, "AGENT");

    char dispatch_message[MESSAGE_SIZE];
    uint8_t packet[PACKET_SIZE];
    Recv recv_msg;

    char dispatch_text[10000] = "DISPATCH: ";
    char relay_text[10000] = {0};
    char agent_text[10000] = {0};

    NodeType node_type=DISPATCH;
    draw(node_type, dispatch_text);
    
    while (1==1){
        KeyEvent k = get_key();        
        if (k.key==KEY_CTRL_Q) {printf("\x1b[2J\x1b[H"); break;}
        if (k.key==KEY_ARROW_LEFT) {
            if (node_type==AGENT) node_type=RELAY; 
            else if (node_type==RELAY) node_type=DISPATCH;
            draw(node_type, node_type==DISPATCH ? dispatch_text : (node_type==RELAY ? relay_text : agent_text));
            continue;
        }
        if (k.key==KEY_ARROW_RIGHT) {
            if (node_type==DISPATCH) node_type=RELAY; 
            else if (node_type==RELAY) node_type=AGENT;
            draw(node_type, node_type==DISPATCH ? dispatch_text : (node_type==RELAY ? relay_text : agent_text));
            continue;
        }
        if (node_type==DISPATCH) {
            if (k.key==KEY_CHAR) {
                size_t len = strlen(dispatch_text);
                dispatch_text[len] = k.ch;
                dispatch_text[len+1] = '\0';
                len = strlen(dispatch_message);
                dispatch_message[len] = k.ch;
                dispatch_message[len+1] = '\0';
            }
            if (k.key==KEY_BACKSPACE) {
                size_t len = strlen(dispatch_text);
                if (len > strlen("DISPATCH: ")) {
                    dispatch_text[len-1] = '\0';
                }
                len = strlen(dispatch_message);
                if (len > 0) {
                    dispatch_message[len-1] = '\0';
                }
            }
            if (k.key==KEY_ENTER) {
                strcat(dispatch_text, "\n[SENT] ENCRYPTED PACKET: ");
                memset(packet, 0, PACKET_SIZE);
                dispatch_send(dispatch_message, packet);
                char buffer[1000] = {0};
                for (size_t i = 0; i < 32; i++) {
                    sprintf(buffer + strlen(buffer), "%02x", packet[i]);
                }
                strcat(dispatch_text, buffer);
                strcat(dispatch_text, "...\n");
                strcat(relay_text, "[RELAY] RELAYING PACKET: ");
                strcat(relay_text, buffer);
                strcat(relay_text, "...\n");
                if (!agent_recv(packet, &recv_msg)) {
                    strcat(agent_text, "MESSAGE TOO OLD\n");
                } else {
                    strcat(agent_text, "[RECEIVED] ");
                    strcat(agent_text, (char*)recv_msg.message);
                    strcat(agent_text, "\n");
                }
                memset(dispatch_message, 0, MESSAGE_SIZE);
                strcat(dispatch_text, "DISPATCH: ");
            }
            draw(node_type, dispatch_text);
        }
        else if (node_type==RELAY) {
            draw(node_type, relay_text);
        }
        else {
            draw(node_type, agent_text);
        }
    }
    return 0;
}