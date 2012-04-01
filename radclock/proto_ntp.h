/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _PROTO_NTP_H
#define _PROTO_NTP_H


/*
 * proto_ntp.h
 * A mix and adaptation
 * Trimed down adaptation of ntp.h and ntp_fp.h to suit the need of the 
 * RADclock all in one file.
 *
 */


/* 
 * -===============================================================-
 * Historic stuff ?? 
 * -===============================================================-
 */

/*
 * TODO: there must be a more sensible way to do that
 */
#define	JAN_1970	2208988800U	/* 1970 - 1900 in seconds */


/* Long and short, integral and fractional parts */
typedef struct {
	uint32_t l_int;
	uint32_t l_fra;
} l_fp;





/* 
 * -===============================================================-
 * Stolen from ntp_fp.h
 * -===============================================================-
 */

/*
 * A unit second in fp format.  Actually 2**(half_the_bits_in_a_long)
 */
#define	FP_SECOND	(0x10000)







/* 
 * -===============================================================-
 * Stolen from ntp.h
 * -===============================================================-
 */

/*
 * NTP protocol parameters.  See section 3.2.6 of the specification.
 */
#define	NTP_VERSION	((u_char)4) /* current version number */
#define	NTP_OLDVERSION	((u_char)1) /* oldest credible version */
#define	DEFAULT_NTP_PORT	123	/* included for non-unix machines */

/*
 * Poll interval parameters
 */
#define NTP_UNREACH	24	/* poll unreach threshold */
#define	NTP_MINPOLL	4	/* log2 min poll interval (16 s) */
#define NTP_MINDPOLL	6	/* log2 default min poll (64 s) */
#define NTP_MAXDPOLL	10	/* log2 default max poll (~17 m) */
#define	NTP_MAXPOLL	17	/* log2 max poll interval (~36 h) */
#define NTP_BURST	8	/* packets in burst */
#define BURST_DELAY	2	/* interburst delay (s) */
#define	RESP_DELAY	1	/* crypto response delay (s) */

/*
 * Values for peer.leap, sys_leap
 */
#define	LEAP_NOWARNING	0x0	/* normal, no leap second warning */
#define	LEAP_ADDSECOND	0x1	/* last minute of day has 61 seconds */
#define	LEAP_DELSECOND	0x2	/* last minute of day has 59 seconds */
#define	LEAP_NOTINSYNC	0x3	/* overload, clock is free running */

/*
 * Values for peer mode and packet mode. Only the modes through
 * MODE_BROADCAST and MODE_BCLIENT appear in the transition
 * function. MODE_CONTROL and MODE_PRIVATE can appear in packets,
 * but those never survive to the transition function.
 * is a
 */
#define	MODE_UNSPEC	0	/* unspecified (old version) */
#define	MODE_ACTIVE	1	/* symmetric active mode */
#define	MODE_PASSIVE	2	/* symmetric passive mode */
#define	MODE_CLIENT	3	/* client mode */
#define	MODE_SERVER	4	/* server mode */
#define	MODE_BROADCAST	5	/* broadcast mode */
/*
 * These can appear in packets
 */
#define	MODE_CONTROL	6	/* control mode */
#define	MODE_PRIVATE	7	/* private mode */
/*
 * This is a madeup mode for broadcast client.
 */
#define	MODE_BCLIENT	6	/* broadcast client mode */


/*
 * To ensure we know the size of crazy packets
 */
#define NTP_MAXEXTEN	1024 /* max extension field size */

/*
 * NTP packet format.  The mac field is optional.  It isn't really
 * an l_fp either, but for now declaring it that way is convenient.
 * See Appendix A in the specification.
 *
 * Note that all u_fp and l_fp values arrive in network byte order
 * and must be converted (except the mac, which isn't, really).
 */
struct ntp_pkt {
	uint8_t		li_vn_mode;	/* leap indicator, version and mode */
	uint8_t		stratum;	/* peer stratum */
	uint8_t		ppoll;		/* peer poll interval */
	int8_t		precision;	/* peer clock precision */
	uint32_t	rootdelay;	/* distance to primary clock */
	uint32_t 	rootdispersion;	/* clock dispersion */
	uint32_t	refid;		/* reference clock ID */
	l_fp		reftime;	/* time peer clock was last updated */
	l_fp		org;		/* originate time stamp */
	l_fp		rec;		/* receive time stamp */
	l_fp		xmt;		/* transmit time stamp */

#define	LEN_PKT_NOMAC	12 * sizeof(u_int32_t) /* min header length */
#define	LEN_PKT_MAC	LEN_PKT_NOMAC +  sizeof(u_int32_t)
#define MIN_MAC_LEN	3 * sizeof(u_int32_t)	/* DES */
#define MAX_MAC_LEN	5 * sizeof(u_int32_t)	/* MD5 */

	/*
	 * The length of the packet less MAC must be a multiple of 64
	 * with an RSA modulus and Diffie-Hellman prime of 64 octets
	 * and maximum host name of 128 octets, the maximum autokey
	 * command is 152 octets and maximum autokey response is 460
	 * octets. A packet can contain no more than one command and one
	 * response, so the maximum total extension field length is 672
	 * octets. But, to handle humungus certificates, the bank must
	 * be broke.
	 */
#ifdef OPENSSL
	uint32_t	exten[NTP_MAXEXTEN / 4]; /* max extension field */
#else /* OPENSSL */
	uint32_t	exten[1];	/* misused */
#endif /* OPENSSL */
	uint8_t	mac[MAX_MAC_LEN]; /* mac */
};


/*
 * A quick dirty alias to have the max possible size of a packet
 */
#define NTP_PKT_MAX_LEN LEN_PKT_NOMAC + 2 * NTP_MAXEXTEN / 8 + MAX_MAC_LEN

/*
 * Stuff for extracting things from li_vn_mode
 */
#define	PKT_MODE(li_vn_mode)	((u_char)((li_vn_mode) & 0x7))
#define	PKT_VERSION(li_vn_mode)	((u_char)(((li_vn_mode) >> 3) & 0x7))
#define	PKT_LEAP(li_vn_mode)	((u_char)(((li_vn_mode) >> 6) & 0x3))

/*
 * Stuff for putting things back into li_vn_mode
 */
#define	PKT_LI_VN_MODE(li, vn, md) \
	((u_char)((((li) << 6) & 0xc0) | (((vn) << 3) & 0x38) | ((md) & 0x7)))


/*
 * Dealing with stratum.  0 gets mapped to 16 incoming, and back to 0
 * on output.
 */
#define	STRATUM_REFCLOCK 	0 /* default stratum */
#define	STRATUM_REFPRIM 	1 /* stratum 1 */
#define	STRATUM_UNSPEC		16 /* unspecified */






#endif
