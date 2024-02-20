#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>

#define PCAP_FAILURE - 1
#define DATAGRAM_SIZE 42
#define MAC_SIZE 6
#define IP_SIZE 4
#define MSG_MAX_SIZE 8
#define PCAP_PKT_CNT_LIMIT 0
#define PCAP_TIMEOUT_LIMIT 1

void show_usage();
void close_all();
void set_arp_spa_tpa(unsigned char * text, unsigned char * data);
void generate_empty_arp_frame(unsigned char * dst, unsigned char * src, unsigned char * data);
void generate_arp(pcap_t * pcap_handle, char * text, int size, unsigned char * data);
void* input_thread(void * peer);
void* arp_listen_and_decode(void * peer);

const unsigned short arp_datagram = 0x0608;
const unsigned short arp_htype = 0x0100;
const unsigned short arp_ptype = 0x0008;
const unsigned char arp_hlen = 0x06;
const unsigned char arp_plen = 0x04;
const unsigned short arp_oper = 0x0100;

const unsigned char peer_one[MAC_SIZE] = {
  0x01,
  0x01,
  0x01,
  0x01,
  0x01,
  0x01
};
const unsigned char peer_two[MAC_SIZE] = {
  0x02,
  0x02,
  0x02,
  0x02,
  0x02,
  0x02
};

pcap_if_t * device;
pcap_t * pcap_handle;
unsigned char * data;

void show_usage() {
  printf("usage: arp-chat [12]\n");
  printf("example: arp-chat 1 => acts as a peer one\n");
  printf("example: arp-chat 2 => acts as a peer two\n");
}

void close_all() {
  puts("Closing...");
  if (pcap_handle)
    pcap_close(pcap_handle);
  if (device)
    pcap_freealldevs(device);
  if (data)
    free(data);
}

void generate_empty_arp_frame(unsigned char * dst, unsigned char * src, unsigned char * data) {
  memcpy(data, dst, MAC_SIZE); // -> dst offset
  memcpy(data + 6, src, MAC_SIZE); // 6 -> src offset
  memcpy(data + 12, & arp_datagram, sizeof(arp_datagram)); // 12 -> ether type offset
  memcpy(data + 14, & arp_htype, sizeof(arp_htype));
  memcpy(data + 16, & arp_ptype, sizeof(arp_ptype));
  data[18] = arp_hlen;
  data[19] = arp_plen;
  memcpy(data + 20, & arp_oper, sizeof(arp_oper));
  memcpy(data + 22, src, MAC_SIZE);
}

void set_arp_spa_tpa(unsigned char * text, unsigned char * data) {
  for (int i = 0; i < MSG_MAX_SIZE / 2; i++) {
    data[28 + i] = (int) text[i];
  }
  for (int j = MSG_MAX_SIZE / 2; j < MSG_MAX_SIZE; j++) {
    data[34 + j] = (int) text[j];
  }
}

void generate_arp(pcap_t * pcap_handle, char * text, int size, unsigned char * data) {
  int times = size / MSG_MAX_SIZE; // how many chunks of 8 we can take
  int remainder = size - (MSG_MAX_SIZE * times); // remainder size
  int remainder_offset = size - remainder;

  // printf("size of string: %d\n", size);
  // printf("times: %d\n", times);
  // printf("remainder: %d\n", remainder);
  // printf("remainder offset: %d\n", remainder_offset);

  if (times > 0) {
    for (int i = 0; i < times; i++) {
      unsigned char * spa_tpa = malloc(MSG_MAX_SIZE);
      memset(spa_tpa, 0, MSG_MAX_SIZE);
      memcpy(spa_tpa, text + (i * MSG_MAX_SIZE), (MSG_MAX_SIZE));
      set_arp_spa_tpa(spa_tpa, data);
      if (PCAP_FAILURE == pcap_sendpacket(pcap_handle, data, DATAGRAM_SIZE)) {
        printf("%s\n", pcap_geterr(pcap_handle));
        free(spa_tpa);
        close_all();
        exit(1);
      }
      free(spa_tpa);
    }
  }

  unsigned char * spa_tpa_remainder = malloc(MSG_MAX_SIZE);
  memset(spa_tpa_remainder, 0, MSG_MAX_SIZE);
  memcpy(spa_tpa_remainder, text + remainder_offset, remainder);

  set_arp_spa_tpa(spa_tpa_remainder, data);
  if (PCAP_FAILURE == pcap_sendpacket(pcap_handle, data, DATAGRAM_SIZE)) {
    printf("%s\n", pcap_geterr(pcap_handle));
    free(spa_tpa_remainder);
    close_all();
    exit(1);
  }
  free(spa_tpa_remainder);
}

void * input_thread(void * peer) {

  unsigned char * name = (unsigned char * ) peer;
  char input[200];
  for (;;) {
    printf("(%02x)> ", * name);
    if (fgets(input, sizeof(input), stdin) == NULL)
      continue;
    if (!device && !pcap_handle && !data)
      continue;
    if (input[0] == '\n' && input[1] == '\0')
      continue;

    generate_arp(pcap_handle, input, strlen(input), data);
    printf("%s", input);
  }
}

void * arp_listen_and_decode(void * peer) {
  unsigned char * name = (unsigned char * ) peer;
  struct pcap_pkthdr packet_header;
  printf("listening for second (%02x) peer...\n\n", * name);
  const unsigned char * packet;
  for (;;) {
    if (!device && !pcap_handle)
      continue;
    packet = pcap_next(pcap_handle, & packet_header);
    if (NULL == packet)
      continue;
    if (memcmp(packet + 6, name, MAC_SIZE) == 0) {
      // yes, this is ugly. But who cares :)
      for (int i = 0; i < MSG_MAX_SIZE / 2; i++) {
        printf("%c", (char) packet[28 + i]);
      }

      for (int j = MSG_MAX_SIZE / 2; j < MSG_MAX_SIZE; j++) {
        printf("%c", (char) packet[34 + j]);
      }

    }

    //printf("packet total length %d\n", packet_header.len);

  }
}

int main(int argc, char * argv[]) {
  // im just too lazy to handle interrupts.... (i will include signal.h later)

  pthread_t th1, th2;
  char error_buffer[PCAP_ERRBUF_SIZE];
  unsigned char dst[MAC_SIZE] = {
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff
  };
  unsigned char src[MAC_SIZE]; // 74:4c:a1:d8:d2:0d
  unsigned char peer[MAC_SIZE];

  if (argc < 2) {
    show_usage();
    return 1;
  }

  switch (atoi(argv[1])) {
  case 1:
    memcpy(src, peer_one, MAC_SIZE);
    memcpy(peer, peer_two, MAC_SIZE);
    puts("acting as a peer one");
    break;
  case 2:
    memcpy(src, peer_two, MAC_SIZE);
    memcpy(peer, peer_one, MAC_SIZE);
    puts("acting as a peer two");
    break;
  default:
    show_usage();
    return 1;
  }

  data = malloc(DATAGRAM_SIZE);

  if (NULL == data) {
    printf("can't allocate memory!\n");
    return 1;
  }

  generate_empty_arp_frame(dst, src, data);

  for (int i = 0; i < DATAGRAM_SIZE; i++) {
    printf("%02x", *(data + i));
  }

  puts("");

  /* Find a device */
  if (PCAP_FAILURE == pcap_findalldevs( & device, error_buffer)) {
    printf("%s\n", error_buffer);
    return 1;
  }

  printf("selected device: %s - %s\n", device -> name, device -> description);

  pcap_handle = pcap_open_live(device -> name, DATAGRAM_SIZE, PCAP_PKT_CNT_LIMIT, PCAP_TIMEOUT_LIMIT, error_buffer);

  if (NULL == pcap_handle) {
    printf("%s\n", error_buffer);
    close_all();
    return 1;
  }
  pthread_create( & th2, NULL, arp_listen_and_decode, peer);
  sleep(1);
  pthread_create( & th1, NULL, input_thread, src);
  for (;;) {
    sleep(1);
  };

  close_all();

  return 0;
}
