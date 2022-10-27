#include "eui64.h"
#include <stdint.h>
#include <stdlib.h>

in6_addr eui64(const ether_addr mac) {
  in6_addr res = {0};
  // TODO
  res.s6_addr[0] = 0xfe;
  res.s6_addr[1] = 0x80;
  res.s6_addr[2] = 0;
  res.s6_addr[3] = 0;
  res.s6_addr[4] = 0;
  res.s6_addr[5] = 0;
  res.s6_addr[6] = 0;
  res.s6_addr[7] = 0;
  res.s6_addr[8] = mac.ether_addr_octet[0] ^ (0x02);
  res.s6_addr[9] = mac.ether_addr_octet[1];
  res.s6_addr[10] = mac.ether_addr_octet[2];
  res.s6_addr[11] = 0xff;
  res.s6_addr[12] = 0xfe;
  res.s6_addr[13] = mac.ether_addr_octet[3];
  res.s6_addr[14] = mac.ether_addr_octet[4];
  res.s6_addr[15] = mac.ether_addr_octet[5];

  return res;
}