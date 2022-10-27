#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
using namespace std;

bool validateAndFillChecksum(uint8_t *packet, size_t len)
{
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;//原有的
  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;//原有的
  if (nxt_header == IPPROTO_UDP)
  {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // printf("upd->uh_ulen:%d",(int)(udp->uh_ulen));
    // length: udp->uh_ulen
    uint16_t length = ntohs(udp->uh_ulen);
    //cout << length << endl;
    uint16_t checksum = udp->uh_sum;
    udp->uh_sum = 0;
    struct in6_addr src = ip6->ip6_src;
    struct in6_addr dst = ip6->ip6_dst;
    uint16_t ulen = udp->uh_ulen;
    uint32_t sum = 0;
    for(int i = 0; i < 8; i++) {
      sum += ntohs(src.s6_addr16[i]);
      //cout << hex << ntohs(src.s6_addr16[i]) << endl;
    }
    for(int i = 0; i < 8; i++) {
      sum += ntohs(dst.s6_addr16[i]);
      //cout << hex << ntohs(src.s6_addr16[i]) << endl;
    }
    uint16_t* itrt = (uint16_t*)&ulen;
    sum += ntohs(*itrt);
    sum += 0x11;
    itrt = (uint16_t*)udp;
    if (length % 2 == 0) {
      for(int i = 0; i < length / 2; i++) {
        sum += ntohs(itrt[i]);
        //cout << hex << ntohs(itrt[i]) << endl;
      }
    } else {
      for(int i = 0; i < length / 2; i++) {
        sum += ntohs(itrt[i]);
        //cout << hex << ntohs(itrt[i]) << endl;
      }
      uint8_t* p = (uint8_t*)udp;
      sum += ((uint16_t)(*(p + length - 1)) << 8);
    }
    sum = sum % (1 << 16) + (sum >> 16);
    sum = sum % (1 << 16) + (sum >> 16);
    if ((uint16_t)sum == 0xFFFF && (uint16_t)checksum == 0xFFFF) {
      udp->uh_sum = 0xFFFF;
      return true;
    }
    else if ((uint16_t)sum == 0 || (uint16_t)sum == 0xFFFF) {
      udp->uh_sum = 0xFFFF;
      return false;
    }
    else if (sum + htons(checksum) == 0xFFFF) {
      udp->uh_sum = (checksum);
      return true;
    }
    else {
      udp->uh_sum = htons(~((uint16_t)sum));
      return false;
    }
  }
  else if (nxt_header == IPPROTO_ICMPV6)
  {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // printf("ip6_un1_plen:%d",(int)(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
    uint16_t length = len - sizeof(struct ip6_hdr);
    uint16_t checksum = icmp->icmp6_cksum;
    icmp->icmp6_cksum = 0;
    struct in6_addr src = ip6->ip6_src;
    struct in6_addr dst = ip6->ip6_dst;
    uint16_t plen = ip6->ip6_plen;
    uint32_t sum = 0;
    for(int i = 0; i < 8; i++) {
      sum += ntohs(src.s6_addr16[i]);
    }
    for(int i = 0; i < 8; i++) {
      sum += ntohs(dst.s6_addr16[i]);
    }
    uint16_t* itrt = (uint16_t*)&plen;
    sum += ntohs(*itrt);
    sum += 0x3A;
    itrt = (uint16_t*)icmp;
    if (length % 2 == 0) {
      for(int i = 0; i < length / 2; i++) {
        sum += ntohs(itrt[i]);
      }
    } else {
      for(int i = 0; i < length / 2; i++) {
        sum += ntohs(itrt[i]);
      }
      uint8_t* p = (uint8_t*)icmp;
      sum += ((uint16_t)(*(p + length - 1)) << 8);
    }
    sum = sum % (1 << 16) + (sum >> 16);
    sum = sum % (1 << 16) + (sum >> 16);
    if ((uint16_t)sum == 0xFFFF && (uint16_t)checksum == 0xFFFF) {
      icmp->icmp6_cksum = 0;
      return true;
    }
    else if (sum + htons(checksum) == 0xFFFF) {
      icmp->icmp6_cksum = (checksum);
      return true;
    }
    else {
      icmp->icmp6_cksum = htons(~((uint16_t)sum));
      return false;
    }
  }
  else
  {
    assert(false);
  }
  return true;
}
