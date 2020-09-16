#ifndef N5305A_DISSESCTOR__H
#define N5305A_DISSESCTOR__H

#include <epan/packet.h>

extern int disectN5305A(tvbuff_t *buffer, packet_info *pinfo, proto_tree *tree, void *data);

extern gint ettN5305A;
extern gint ettFlags;

extern int hfFlagsType;
extern const int *hfFlags[17];
extern int hfPacketDirection;
extern int hfPacketLength;
extern int hfUnknown1;
extern int hfCookie;
extern int hfStatus;
extern int hfRawData;

#endif /*N5305A_DISSESCTOR__H*/
