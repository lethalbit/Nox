#ifndef N5305A_DISSESCTOR__H
#define N5305A_DISSESCTOR__H

#include <epan/packet.h>

extern int disectN5305A(tvbuff_t *buffer, packet_info *pinfo, proto_tree *tree, void *data);

extern gint ettN5305A;

extern int flagsType;
extern int packetDirection;
extern int packetLength;

extern tvbuff_t *dirHost;
extern tvbuff_t *dirAnalyzer;

#endif /*N5305A_DISSESCTOR__H*/
