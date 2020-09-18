#ifndef N5305A_FRAME_DISSECTOR__H
#define N5305A_FRAME_DISSECTOR__H

#ifdef __cplusplus
extern "C"
{
#endif

extern void registerProtocolN5305AFraming(void);
extern void registerDissectorN5305AFraming(void);

extern void registerProtocolN5305ATransaction(void);
extern void registerDissectorN5305ATransaction(void);

#ifdef __cplusplus
}
#endif

#endif /*N5305A_FRAME_DISSECTOR__H*/
