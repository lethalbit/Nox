#ifndef N5305A_FRAME_DISSECTOR__H
#define N5305A_FRAME_DISSECTOR__H

#include <epan/packet.h>

extern dissector_handle_t transactionDissector;
extern int32_t ettN5305ATransact;
extern int32_t hfTransactCookie;
extern int32_t hfTransactData;

extern void registerProtocolN5305ATransaction(void);
extern void registerDissectorN5305ATransaction(void);



#endif /*N5305A_FRAME_DISSECTOR__H*/
