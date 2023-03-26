#ifndef __XDP_STRUCTS_H
#define __XDP_STRUCTS_H


#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in6.h> /* For struct in6_addr. */
#include "xdp_consts.h"

// Segment Routing Extension Header (SRH)
// https://datatracker.ietf.org/doc/draft-ietf-6man-segment-routing-header/
struct srhhdr
{
    __u8 nextHdr;
    __u8 hdrExtLen;
    __u8 routingType;
    __u8 segmentsLeft;
    __u8 lastEntry;
    __u8 flags;
    __u16 tag;
    // cf. 5.3. Encoding of Tags Field/ https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding
    // __u8 gtpMessageType : 4; // least significant 4 bits of tag field
    struct in6_addr segments[0];
};

struct probe_data {
	__u8	h_dest[ETH_ALEN];
	__u8	h_source[ETH_ALEN];
	__be16		    h_proto;
    struct in6_addr v6_srcaddr;
    struct in6_addr v6_dstaddr;
    __u8 nextHdr;
    __u8 hdrExtLen;
    __u8 routingType;
    __u8 segmentsLeft;
    __u8 lastEntry;
    __u8 flags;
    __u16 tag;
    struct in6_addr segments[MAX_SEGMENTLIST_ENTRIES];
};

#endif
