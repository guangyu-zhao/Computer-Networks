#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
using namespace std;

map<TableIndex, RoutingTableEntry> RoutingTable;

void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  if(insert){
    RoutingTable[TableIndex(entry.addr, entry.len)] = entry;
  } else {
    map<TableIndex, RoutingTableEntry>::iterator search = RoutingTable.find(TableIndex(entry.addr, entry.len));
    if (search != RoutingTable.end()){
      RoutingTable.erase(search);
    }
  }
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  int max_len = 0;
  bool found = false;
  for(map<TableIndex, RoutingTableEntry>::iterator search = RoutingTable.begin(); search != RoutingTable.end(); search++){
    in6_addr query_subnet = addr & len_to_mask(search->first.len);
    in6_addr iter_subnet = search->first.addr & len_to_mask(search->first.len);
    if(query_subnet == iter_subnet){
      if(search->first.len > max_len){
        max_len = search->first.len;
        *nexthop = search->second.nexthop;
        *if_index = search->second.if_index;
        found = true;
      }
    }
  }
  return found;
}

int log2_intPower(int n) {
	int ret = 0;
	while (n != 1) {
		if (n % 2 == 0) {
			n /= 2;
			ret++;
		}
		else return -1;
	}
	return ret;
}

int mask_to_len(const in6_addr mask) {
  // TODO
  int ret = 0;
  for(int i = 0; i < 8; i++){
    int tmp = 65536 - (int)ntohs(mask.s6_addr16[i]);
    if(log2_intPower(tmp) != -1){
      ret += (16 - log2_intPower(tmp));
    }
    else return -1; 
  }
  return ret;
}

in6_addr len_to_mask(int len) {
  // TODO
  in6_addr mask;
  for(int i = 0; i < 8; i++){
    mask.s6_addr16[i] = 0;
  }
  if(len > 128 || len < 0) {
    return mask;
  }
  int byte = len / 8;
  for(int i = 0; i < byte; i++){
    mask.s6_addr[i] = 0xFF;
  }
  int p = len - 8 * byte;
  mask.s6_addr[byte] = 0x100 - (1 << (8 - p));
  return mask;
}