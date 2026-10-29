#ifndef RTPE_TC_OFFLOAD_H_
#define RTPE_TC_OFFLOAD_H_

#include <stdbool.h>

struct packet_stream;

bool tc_offload_wanted(void);
bool tc_offload_is_active(void);
bool tc_offload_init(void);
void tc_offload_shutdown(void);
bool tc_offload_add_stream(struct packet_stream *stream);
void tc_offload_del_stream(struct packet_stream *stream);

#endif
