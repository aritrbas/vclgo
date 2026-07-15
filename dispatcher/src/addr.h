#ifndef VCLGO_ADDR_H
#define VCLGO_ADDR_H

#include "internal.h"

int vclgo_sockaddr_to_endpt(const struct sockaddr *sa, socklen_t sal,
                            vppcom_endpt_t *ep, uint8_t ip_out[16]);

int vclgo_endpt_to_sockaddr(const vppcom_endpt_t *ep,
                            struct sockaddr *addr, socklen_t *addrlen);

#endif
