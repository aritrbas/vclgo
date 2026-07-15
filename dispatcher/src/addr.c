/*
 * addr.c — struct sockaddr <-> vppcom_endpt_t conversion, and helpers
 * for building the little scratch buffers VLS wants for its endpoint's
 * `uint8_t *ip` pointer.
 *
 * Every VLS call takes a `vppcom_endpt_t *` whose `ip` field is a raw
 * byte pointer into a caller-owned buffer. To make the per-call code
 * concise we stash both the vppcom_endpt_t and the underlying IP bytes
 * in a single stack-allocated helper.
 */

#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>

int vclgo_sockaddr_to_endpt(const struct sockaddr *sa, socklen_t sal,
                            vppcom_endpt_t *ep, uint8_t ip_out[16])
{
    memset(ep, 0, sizeof *ep);
    if (!sa) return vclgo_set_errno(EINVAL);

    if (sa->sa_family == AF_INET && sal >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        ep->is_ip4 = VPPCOM_IS_IP4;
        memcpy(ip_out, &sin->sin_addr.s_addr, 4);
        ep->ip   = ip_out;
        ep->port = sin->sin_port;
        return 0;
    }
    if (sa->sa_family == AF_INET6 && sal >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        ep->is_ip4 = VPPCOM_IS_IP6;
        memcpy(ip_out, &sin6->sin6_addr, 16);
        ep->ip   = ip_out;
        ep->port = sin6->sin6_port;
        return 0;
    }
    return vclgo_set_errno(EAFNOSUPPORT);
}

int vclgo_endpt_to_sockaddr(const vppcom_endpt_t *ep,
                            struct sockaddr *addr, socklen_t *addrlen)
{
    if (!addr || !addrlen) return vclgo_set_errno(EINVAL);
    if (ep->is_ip4 == VPPCOM_IS_IP4) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return vclgo_set_errno(EINVAL);
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_port   = ep->port;
        memcpy(&sin.sin_addr.s_addr, ep->ip, 4);
        memcpy(addr, &sin, sizeof sin);
        *addrlen = sizeof sin;
        return 0;
    } else {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return vclgo_set_errno(EINVAL);
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof sin6);
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port   = ep->port;
        memcpy(&sin6.sin6_addr, ep->ip, 16);
        memcpy(addr, &sin6, sizeof sin6);
        *addrlen = sizeof sin6;
        return 0;
    }
}
