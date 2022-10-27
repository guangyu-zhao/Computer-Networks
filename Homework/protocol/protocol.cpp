#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
using namespace std;

RipErrorCode disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // cout << ":::::::::::::::::::::::::::::::" << endl << sizeof(udphdr) << endl;
  // TODO
  uint16_t plen = ntohs(*(uint16_t*)(packet + 4));
  //cout << len << ' ' << plen << endl;
  if(len != (uint32_t)plen + 40) return RipErrorCode::ERR_LENGTH;

  uint16_t nxt = *(uint16_t*)(packet + 6) % (1 << 8);
  //cout << nxt << endl;
  if(nxt != 17) return RipErrorCode::ERR_IP_NEXT_HEADER_NOT_UDP;

  if(plen < 8) return RipErrorCode::ERR_LENGTH;

  uint16_t src = ntohs(*(uint16_t*)(packet + 40)), dst = ntohs(*(uint16_t*)(packet + 42));
  //cout << src << dst << endl;
  if(src != 521 || dst != 521) return RipErrorCode::ERR_BAD_UDP_PORT;

  uint16_t ulen = ntohs(*(uint16_t*)(packet + 44));
  //cout << ulen << endl;
  //cout << ntohs(output->numEntries) << endl;
  if((ulen - 12) % 20 != 0) return RipErrorCode::ERR_LENGTH;

  //cout << *(uint16_t*)(packet + 48) % (1 << 8) << endl;
  if(*(uint16_t*)(packet + 48) % (1 << 8) != 1 && *(uint16_t*)(packet + 48) % (1 << 8) != 2) return RipErrorCode::ERR_RIP_BAD_COMMAND;

  //cout << *(uint16_t*)(packet + 49) % (1 << 8) << endl;
  if(*(uint16_t*)(packet + 49) % (1 << 8) != 1) return RipErrorCode::ERR_RIP_BAD_VERSION;

  //cout << *(uint16_t*)(packet + 50) << endl;
  if(*(uint16_t*)(packet + 50) != 0) return RipErrorCode::ERR_RIP_BAD_ZERO;

  for(int i = 0; i < (ulen - 12) / 20; i++){
    uint16_t mc = *(uint16_t*)(packet + 70 + 20 * i) / (1 << 8);
    uint16_t pl = *(uint16_t*)(packet + 70 + 20 * i) % (1 << 8);
    uint16_t rt = ntohs(*(uint16_t*)(packet + 68 + 20 * i));
    //cout << "mc" << mc << ' ' << "pl" << pl << ' ' << "rt" << rt << endl;
    if(mc == 0xFF){
      if(pl != 0) return RipErrorCode::ERR_RIP_BAD_PREFIX_LEN;
      if(rt != 0) return RipErrorCode::ERR_RIP_BAD_ROUTE_TAG;
    }
  }

  for(int i = 0; i < (ulen - 12) / 20; i++){
    uint16_t mc = *(uint16_t*)(packet + 70 + 20 * i) / (1 << 8);
    uint16_t pl = *(uint16_t*)(packet + 70 + 20 * i) % (1 << 8);
    uint16_t rt = ntohs(*(uint16_t*)(packet + 68 + 20 * i));
    //cout << mc << ' ' << pl << ' ' << rt << endl;
    if(mc != 0xFF){
      if(mc < 1 || mc > 16) return RipErrorCode::ERR_RIP_BAD_METRIC;
      if(pl > 128) return RipErrorCode::ERR_RIP_BAD_PREFIX_LEN;
    }
  }

  for(int i = 0; i < (ulen - 12) / 20; i++){
    uint16_t pl = *(uint16_t*)(packet + 70 + 20 * i) % (1 << 8);
    uint16_t* pref = (uint16_t*)(packet + 52 + 20 * i);
    uint16_t pre = (pl + 15) / 16;
    uint16_t bits = pl % 16;
    uint16_t mc = *(uint16_t*)(packet + 70 + 20 * i) / (1 << 8);
    if(mc != 0xFF){
      if(bits){
        uint16_t edge = ntohs(*(pref + pre - 1));
        if(edge % (1 << (16 - bits))) return RipErrorCode::ERR_RIP_INCONSISTENT_PREFIX_LENGTH;
      }
      for(int i = 0; i < 8 - pre; i++){
        if(*(pref + pre + i) != 0) return RipErrorCode::ERR_RIP_INCONSISTENT_PREFIX_LENGTH;
      }
    }
  }

  output->numEntries = (ulen - 12) / 20;
  output->command = *(uint16_t*)(packet + 48) % (1 << 8);

  for(int i = 0; i < (ulen - 12) / 20; i++){
    output->entries[i].metric = *(uint16_t*)(packet + 70 + 20 * i) / (1 << 8);
    output->entries[i].route_tag = *(uint16_t*)(packet + 68 + 20 * i);
    output->entries[i].prefix_len = *(uint16_t*)(packet + 70 + 20 * i) % (1 << 8);
    for(int j = 0; j < 8; j++){
      output->entries[i].prefix_or_nh.s6_addr16[j] = *(uint16_t*)(packet + 52 + 20 * i + j * 2);
    }
  }
  
  return RipErrorCode::SUCCESS;
}

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO
  // cout << "start" << endl;
  buffer[0] = rip->command;
  buffer[1] = 1;
  buffer[2] = 0;
  buffer[3] = 0;
  // cout << "end" << endl;
  for(int i = 0; i < rip->numEntries; i++){
    for(int j = 0; j < 16; j++){
      buffer[4 + i * 20 + j] = rip->entries[i].prefix_or_nh.s6_addr[j];
    }
    buffer[4 + i * 20 + 17] = rip->entries[i].route_tag / (1 << 8);
    buffer[4 + i * 20 + 16] = rip->entries[i].route_tag % (1 << 8);
    buffer[4 + i * 20 + 18] = rip->entries[i].prefix_len;
    buffer[4 + i * 20 + 19] = rip->entries[i].metric;
  }
  return rip->numEntries * 20 + 4;
}