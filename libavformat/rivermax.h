/*
 * RIVERMAX definitions
 * Copyright (c) 2002 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef AVFORMAT_RIVERMAX_H
#define AVFORMAT_RIVERMAX_H

#include <stdint.h>
#include "avformat.h"
#include "rivermaxcodes.h"
#include "rtpdec.h"
#include "network.h"
#include "httpauth.h"

#include "libavutil/log.h"
#include "libavutil/opt.h"

/**
 * Network layer over which RTP/etc packet data will be transported.
 */
enum RIVERMAXLowerTransport {
    RIVERMAX_LOWER_TRANSPORT_UDP = 0,           /**< UDP/unicast */
    RIVERMAX_LOWER_TRANSPORT_TCP = 1,           /**< TCP; interleaved in RIVERMAX */
    RIVERMAX_LOWER_TRANSPORT_UDP_MULTICAST = 2, /**< UDP/multicast */
    RIVERMAX_LOWER_TRANSPORT_NB,
    RIVERMAX_LOWER_TRANSPORT_HTTP = 8,          /**< HTTP tunneled - not a proper
                                                 transport mode as such,
                                                 only for use via AVOptions */
    RIVERMAX_LOWER_TRANSPORT_HTTPS,             /**< HTTPS tunneled */
    RIVERMAX_LOWER_TRANSPORT_CUSTOM = 16,       /**< Custom IO - not a public
                                                 option for lower_transport_mask,
                                                 but set in the SDP demuxer based
                                                 on a flag. */
};

/**
 * Packet profile of the data that we will be receiving. Real servers
 * commonly send RDT (although they can sometimes send RTP as well),
 * whereas most others will send RTP.
 */
enum RIVERMAXTransport {
    RIVERMAX_TRANSPORT_RTP, /**< Standards-compliant RTP */
    RIVERMAX_TRANSPORT_RDT, /**< Realmedia Data Transport */
    RIVERMAX_TRANSPORT_RAW, /**< Raw data (over UDP) */
    RIVERMAX_TRANSPORT_NB
};

/**
 * Transport mode for the RIVERMAX data. This may be plain, or
 * tunneled, which is done over HTTP.
 */
enum RIVERMAXControlTransport {
    RIVERMAX_MODE_PLAIN,   /**< Normal RIVERMAX */
    RIVERMAX_MODE_TUNNEL   /**< RIVERMAX over HTTP (tunneling) */
};

#define RIVERMAX_DEFAULT_PORT   554
#define RIVERMAXS_DEFAULT_PORT  322
#define RIVERMAX_MAX_TRANSPORTS 8
#define RIVERMAX_TCP_MAX_PACKET_SIZE 1472
#define RIVERMAX_DEFAULT_NB_AUDIO_CHANNELS 1
#define RIVERMAX_DEFAULT_AUDIO_SAMPLERATE 44100
#define RIVERMAX_RTP_PORT_MIN 5000
#define RIVERMAX_RTP_PORT_MAX 65000

/**
 * This describes a single item in the "Transport:" line of one stream as
 * negotiated by the SETUP RIVERMAX command. Multiple transports are comma-
 * separated ("Transport: x-read-rdt/tcp;interleaved=0-1,rtp/avp/udp;
 * client_port=1000-1001;server_port=1800-1801") and described in separate
 * RIVERMAXTransportFields.
 */
typedef struct RIVERMAXTransportField {
    /** interleave ids, if TCP transport; each TCP/RIVERMAX data packet starts
     * with a '$', stream length and stream ID. If the stream ID is within
     * the range of this interleaved_min-max, then the packet belongs to
     * this stream. */
    int interleaved_min, interleaved_max;

    /** UDP multicast port range; the ports to which we should connect to
     * receive multicast UDP data. */
    int port_min, port_max;

    /** UDP client ports; these should be the local ports of the UDP RTP
     * (and RTCP) sockets over which we receive RTP/RTCP data. */
    int client_port_min, client_port_max;

    /** UDP unicast server port range; the ports to which we should connect
     * to receive unicast UDP RTP/RTCP data. */
    int server_port_min, server_port_max;

    /** time-to-live value (required for multicast); the amount of HOPs that
     * packets will be allowed to make before being discarded. */
    int ttl;

    /** transport set to record data */
    int mode_record;

    struct sockaddr_storage destination; /**< destination IP address */
    char source[INET6_ADDRSTRLEN + 1]; /**< source IP address */

    /** data/packet transport protocol; e.g. RTP or RDT */
    enum RIVERMAXTransport transport;

    /** network layer transport protocol; e.g. TCP or UDP uni-/multicast */
    enum RIVERMAXLowerTransport lower_transport;
} RIVERMAXTransportField;

/**
 * This describes the server response to each RIVERMAX command.
 */
typedef struct RIVERMAXMessageHeader {
    /** length of the data following this header */
    int content_length;

    enum RIVERMAXStatusCode status_code; /**< response code from server */

    /** number of items in the 'transports' variable below */
    int nb_transports;

    /** Time range of the streams that the server will stream. In
     * AV_TIME_BASE unit, AV_NOPTS_VALUE if not used */
    int64_t range_start, range_end;

    /** describes the complete "Transport:" line of the server in response
     * to a SETUP RIVERMAX command by the client */
    RIVERMAXTransportField transports[RIVERMAX_MAX_TRANSPORTS];

    int seq;                         /**< sequence number */

    /** the "Session:" field. This value is initially set by the server and
     * should be re-transmitted by the client in every RIVERMAX command. */
    char session_id[512];

    /** the "Location:" field. This value is used to handle redirection.
     */
    char location[4096];

    /** the "RealChallenge1:" field from the server */
    char real_challenge[64];

    /** the "Server: field, which can be used to identify some special-case
     * servers that are not 100% standards-compliant. We use this to identify
     * Windows Media Server, which has a value "WMServer/v.e.r.sion", where
     * version is a sequence of digits (e.g. 9.0.0.3372). Helix/Real servers
     * use something like "Helix [..] Server Version v.e.r.sion (platform)
     * (RealServer compatible)" or "RealServer Version v.e.r.sion (platform)",
     * where platform is the output of $uname -msr | sed 's/ /-/g'. */
    char server[64];

    /** The "timeout" comes as part of the server response to the "SETUP"
     * command, in the "Session: <xyz>[;timeout=<value>]" line. It is the
     * time, in seconds, that the server will go without traffic over the
     * RIVERMAX/TCP connection before it closes the connection. To prevent
     * this, sent dummy requests (e.g. OPTIONS) with intervals smaller
     * than this value. */
    int timeout;

    /** The "Notice" or "X-Notice" field value. See
     * http://tools.ietf.org/html/draft-stiemerling-rivermax-announce-00
     * for a complete list of supported values. */
    int notice;

    /** The "reason" is meant to specify better the meaning of the error code
     * returned
     */
    char reason[256];

    /**
     * Content type header
     */
    char content_type[64];
} RIVERMAXMessageHeader;

/**
 * Client state, i.e. whether we are currently receiving data (PLAYING) or
 * setup-but-not-receiving (PAUSED). State can be changed in applications
 * by calling av_read_play/pause().
 */
enum RIVERMAXClientState {
    RIVERMAX_STATE_IDLE,    /**< not initialized */
    RIVERMAX_STATE_STREAMING, /**< initialized and sending/receiving data */
    RIVERMAX_STATE_PAUSED,  /**< initialized, but not receiving data */
    RIVERMAX_STATE_SEEKING, /**< initialized, requesting a seek */
};

/**
 * Identify particular servers that require special handling, such as
 * standards-incompliant "Transport:" lines in the SETUP request.
 */
enum RIVERMAXServerType {
    RIVERMAX_SERVER_RTP,  /**< Standards-compliant RTP-server */
    RIVERMAX_SERVER_REAL, /**< Realmedia-style server */
    RIVERMAX_SERVER_WMS,  /**< Windows Media server */
    RIVERMAX_SERVER_NB
};

/**
 * Private data for the RIVERMAX demuxer.
 *
 * @todo Use AVIOContext instead of URLContext
 */
typedef struct RIVERMAXState {
    const AVClass *class;             /**< Class for private options. */
    URLContext *rivermax_hd; /* RIVERMAX TCP connection handle */

    /** number of items in the 'rivermax_streams' variable */
    int nb_rivermax_streams;

    struct RIVERMAXStream **rivermax_streams; /**< streams in this session */

    /** indicator of whether we are currently receiving data from the
     * server. Basically this isn't more than a simple cache of the
     * last PLAY/PAUSE command sent to the server, to make sure we don't
     * send 2x the same unexpectedly or commands in the wrong state. */
    enum RIVERMAXClientState state;

    /** the seek value requested when calling av_seek_frame(). This value
     * is subsequently used as part of the "Range" parameter when emitting
     * the RIVERMAX PLAY command. If we are currently playing, this command is
     * called instantly. If we are currently paused, this command is called
     * whenever we resume playback. Either way, the value is only used once,
     * see rivermax_read_play() and rivermax_read_seek(). */
    int64_t seek_timestamp;

    int seq;                          /**< RIVERMAX command sequence number */

    /** copy of RIVERMAXMessageHeader->session_id, i.e. the server-provided session
     * identifier that the client should re-transmit in each RIVERMAX command */
    char session_id[512];

    /** copy of RIVERMAXMessageHeader->timeout, i.e. the time (in seconds) that
     * the server will go without traffic on the RIVERMAX/TCP line before it
     * closes the connection. */
    int timeout;

    /** timestamp of the last RIVERMAX command that we sent to the RIVERMAX server.
     * This is used to calculate when to send dummy commands to keep the
     * connection alive, in conjunction with timeout. */
    int64_t last_cmd_time;

    /** the negotiated data/packet transport protocol; e.g. RTP or RDT */
    enum RIVERMAXTransport transport;

    /** the negotiated network layer transport protocol; e.g. TCP or UDP
     * uni-/multicast */
    enum RIVERMAXLowerTransport lower_transport;

    /** brand of server that we're talking to; e.g. WMS, REAL or other.
     * Detected based on the value of RIVERMAXMessageHeader->server or the presence
     * of RIVERMAXMessageHeader->real_challenge */
    enum RIVERMAXServerType server_type;

    /** the "RealChallenge1:" field from the server */
    char real_challenge[64];

    /** plaintext authorization line (username:password) */
    char auth[128];

    /** authentication state */
    HTTPAuthState auth_state;

    /** The last reply of the server to a RIVERMAX command */
    char last_reply[2048]; /* XXX: allocate ? */

    /** RIVERMAXStream->transport_priv of the last stream that we read a
     * packet from */
    void *cur_transport_priv;

    /** The following are used for Real stream selection */
    //@{
    /** whether we need to send a "SET_PARAMETER Subscribe:" command */
    int need_subscription;

    /** stream setup during the last frame read. This is used to detect if
     * we need to subscribe or unsubscribe to any new streams. */
    enum AVDiscard *real_setup_cache;

    /** current stream setup. This is a temporary buffer used to compare
     * current setup to previous frame setup. */
    enum AVDiscard *real_setup;

    /** the last value of the "SET_PARAMETER Subscribe:" RIVERMAX command.
     * this is used to send the same "Unsubscribe:" if stream setup changed,
     * before sending a new "Subscribe:" command. */
    char last_subscription[1024];
    //@}

    /** The following are used for RTP/ASF streams */
    //@{
    /** ASF demuxer context for the embedded ASF stream from WMS servers */
    AVFormatContext *asf_ctx;

    /** cache for position of the asf demuxer, since we load a new
     * data packet in the bytecontext for each incoming RIVERMAX packet. */
    uint64_t asf_pb_pos;
    //@}

    /** some MS RIVERMAX streams contain a URL in the SDP that we need to use
     * for all subsequent RIVERMAX requests, rather than the input URI; in
     * other cases, this is a copy of AVFormatContext->filename. */
    char control_uri[1024];

    /** The following are used for parsing raw mpegts in udp */
    //@{
    struct MpegTSContext *ts;
    int recvbuf_pos;
    int recvbuf_len;
    //@}

    /** Additional output handle, used when input and output are done
     * separately, eg for HTTP tunneling. */
    URLContext *rivermax_hd_out;

    /** RIVERMAX transport mode, such as plain or tunneled. */
    enum RIVERMAXControlTransport control_transport;

    /* Number of RTCP BYE packets the RIVERMAX session has received.
     * An EOF is propagated back if nb_byes == nb_streams.
     * This is reset after a seek. */
    int nb_byes;

    /** Reusable buffer for receiving packets */
    uint8_t* recvbuf;

    /**
     * A mask with all requested transport methods
     */
    int lower_transport_mask;

    /**
     * The number of returned packets
     */
    uint64_t packets;

    /**
     * Polling array for udp
     */
    struct pollfd *p;
    int max_p;

    /**
     * Whether the server supports the GET_PARAMETER method.
     */
    int get_parameter_supported;

    /**
     * Do not begin to play the stream immediately.
     */
    int initial_pause;

    /**
     * Option flags for the chained RTP muxer.
     */
    int rtp_muxer_flags;

    /** Whether the server accepts the x-Dynamic-Rate header */
    int accept_dynamic_rate;

    /**
     * Various option flags for the RIVERMAX muxer/demuxer.
     */
    int rivermax_flags;

    /**
     * Mask of all requested media types
     */
    int media_type_mask;

    /**
     * Minimum and maximum local UDP ports.
     */
    int rtp_port_min, rtp_port_max;

    /**
     * Timeout to wait for incoming connections.
     */
    int initial_timeout;

    /**
     * timeout of socket i/o operations.
     */
    int stimeout;

    /**
     * Size of RTP packet reordering queue.
     */
    int reordering_queue_size;

    /**
     * User-Agent string
     */
    char *user_agent;

    char default_lang[4];
    int buffer_size;
    int pkt_size;
} RIVERMAXState;

#define RIVERMAX_FLAG_FILTER_SRC  0x1    /**< Filter incoming UDP packets -
                                          receive packets only from the right
                                          source address and port. */
#define RIVERMAX_FLAG_LISTEN      0x2    /**< Wait for incoming connections. */
#define RIVERMAX_FLAG_CUSTOM_IO   0x4    /**< Do all IO via the AVIOContext. */
#define RIVERMAX_FLAG_RTCP_TO_SOURCE 0x8 /**< Send RTCP packets to the source
                                          address of received packets. */
#define RIVERMAX_FLAG_PREFER_TCP  0x10   /**< Try RTP via TCP first if possible. */

typedef struct RIVERMAXSource {
    char addr[128]; /**< Source-specific multicast include source IP address (from SDP content) */
} RIVERMAXSource;

/**
 * Describe a single stream, as identified by a single m= line block in the
 * SDP content. In the case of RDT, one RIVERMAXStream can represent multiple
 * AVStreams. In this case, each AVStream in this set has similar content
 * (but different codec/bitrate).
 */
typedef struct RIVERMAXStream {
    URLContext *rtp_handle;   /**< RTP stream handle (if UDP) */
    void *transport_priv; /**< RTP/RDT parse context if input, RTP AVFormatContext if output */

    /** corresponding stream index, if any. -1 if none (MPEG2TS case) */
    int stream_index;

    /** interleave IDs; copies of RIVERMAXTransportField->interleaved_min/max
     * for the selected transport. Only used for TCP. */
    int interleaved_min, interleaved_max;

    char control_url[1024];   /**< url for this stream (from SDP) */

    /** The following are used only in SDP, not RIVERMAX */
    //@{
    int sdp_port;             /**< port (from SDP content) */
    struct sockaddr_storage sdp_ip; /**< IP address (from SDP content) */
    int nb_include_source_addrs; /**< Number of source-specific multicast include source IP addresses (from SDP content) */
    struct RIVERMAXSource **include_source_addrs; /**< Source-specific multicast include source IP addresses (from SDP content) */
    int nb_exclude_source_addrs; /**< Number of source-specific multicast exclude source IP addresses (from SDP content) */
    struct RIVERMAXSource **exclude_source_addrs; /**< Source-specific multicast exclude source IP addresses (from SDP content) */
    int sdp_ttl;              /**< IP Time-To-Live (from SDP content) */
    int sdp_payload_type;     /**< payload type */
    //@}

    /** The following are used for dynamic protocols (rtpdec_*.c/rdt.c) */
    //@{
    /** handler structure */
    const RTPDynamicProtocolHandler *dynamic_handler;

    /** private data associated with the dynamic protocol */
    PayloadContext *dynamic_protocol_context;
    //@}

    /** Enable sending RTCP feedback messages according to RFC 4585 */
    int feedback;

    /** SSRC for this stream, to allow identifying RTCP packets before the first RTP packet */
    uint32_t ssrc;

    char crypto_suite[40];
    char crypto_params[100];
} RIVERMAXStream;

void ff_rivermax_parse_line(AVFormatContext *s,
                        RIVERMAXMessageHeader *reply, const char *buf,
                        RIVERMAXState *rt, const char *method);

/**
 * Send a command to the RIVERMAX server without waiting for the reply.
 *
 * @see rivermax_send_cmd_with_content_async
 */
int ff_rivermax_send_cmd_async(AVFormatContext *s, const char *method,
                           const char *url, const char *headers);

/**
 * Send a command to the RIVERMAX server and wait for the reply.
 *
 * @param s RIVERMAX (de)muxer context
 * @param method the method for the request
 * @param url the target url for the request
 * @param headers extra header lines to include in the request
 * @param reply pointer where the RIVERMAX message header will be stored
 * @param content_ptr pointer where the RIVERMAX message body, if any, will
 *                    be stored (length is in reply)
 * @param send_content if non-null, the data to send as request body content
 * @param send_content_length the length of the send_content data, or 0 if
 *                            send_content is null
 *
 * @return zero if success, nonzero otherwise
 */
int ff_rivermax_send_cmd_with_content(AVFormatContext *s,
                                  const char *method, const char *url,
                                  const char *headers,
                                  RIVERMAXMessageHeader *reply,
                                  unsigned char **content_ptr,
                                  const unsigned char *send_content,
                                  int send_content_length);

/**
 * Send a command to the RIVERMAX server and wait for the reply.
 *
 * @see rivermax_send_cmd_with_content
 */
int ff_rivermax_send_cmd(AVFormatContext *s, const char *method,
                     const char *url, const char *headers,
                     RIVERMAXMessageHeader *reply, unsigned char **content_ptr);

/**
 * Read a RIVERMAX message from the server, or prepare to read data
 * packets if we're reading data interleaved over the TCP/RIVERMAX
 * connection as well.
 *
 * @param s RIVERMAX (de)muxer context
 * @param reply pointer where the RIVERMAX message header will be stored
 * @param content_ptr pointer where the RIVERMAX message body, if any, will
 *                    be stored (length is in reply)
 * @param return_on_interleaved_data whether the function may return if we
 *                   encounter a data marker ('$'), which precedes data
 *                   packets over interleaved TCP/RIVERMAX connections. If this
 *                   is set, this function will return 1 after encountering
 *                   a '$'. If it is not set, the function will skip any
 *                   data packets (if they are encountered), until a reply
 *                   has been fully parsed. If no more data is available
 *                   without parsing a reply, it will return an error.
 * @param method the RIVERMAX method this is a reply to. This affects how
 *               some response headers are acted upon. May be NULL.
 *
 * @return 1 if a data packets is ready to be received, -1 on error,
 *          and 0 on success.
 */
int ff_rivermax_read_reply(AVFormatContext *s, RIVERMAXMessageHeader *reply,
                       unsigned char **content_ptr,
                       int return_on_interleaved_data, const char *method);

/**
 * Skip a RTP/TCP interleaved packet.
 */
void ff_rivermax_skip_packet(AVFormatContext *s);

/**
 * Connect to the RIVERMAX server and set up the individual media streams.
 * This can be used for both muxers and demuxers.
 *
 * @param s RIVERMAX (de)muxer context
 *
 * @return 0 on success, < 0 on error. Cleans up all allocations done
 *          within the function on error.
 */
int ff_rivermax_connect(AVFormatContext *s);

/**
 * Close and free all streams within the RIVERMAX (de)muxer
 *
 * @param s RIVERMAX (de)muxer context
 */
void ff_rivermax_close_streams(AVFormatContext *s);

/**
 * Close all connection handles within the RIVERMAX (de)muxer
 *
 * @param s RIVERMAX (de)muxer context
 */
void ff_rivermax_close_connections(AVFormatContext *s);

/**
 * Get the description of the stream and set up the RIVERMAXStream child
 * objects.
 */
int ff_rtsp_setup_input_streams(AVFormatContext *s, RIVERMAXMessageHeader *reply);

/**
 * Announce the stream to the server and set up the RIVERMAXStream child
 * objects for each media stream.
 */
int ff_rivermax_setup_output_streams(AVFormatContext *s, const char *addr);

/**
 * Parse RIVERMAX commands (OPTIONS, PAUSE and TEARDOWN) during streaming in
 * listen mode.
 */
// FORWARD DECL
int ff_rtsp_parse_streaming_commands(AVFormatContext *s);

/**
 * Parse an SDP description of streams by populating an RIVERMAXState struct
 * within the AVFormatContext; also allocate the RTP streams and the
 * pollfd array used for UDP streams.
 */
int ff_sdp_parse1(AVFormatContext *s, const char *content);

/**
 * Receive one RTP packet from an TCP interleaved RIVERMAX stream.
 */
int ff_rtsp_tcp_read_packet(AVFormatContext *s, RIVERMAXStream **privermax_st,
                            uint8_t *buf, int buf_size);

/**
 * Send buffered packets over TCP.
 */
int ff_rtsp_tcp_write_packet(AVFormatContext *s, RIVERMAXStream *rivermax_st);

/**
 * Receive one packet from the RIVERMAXStreams set up in the AVFormatContext
 * (which should contain a RIVERMAXState struct as priv_data).
 */
int ff_rivermax_fetch_packet(AVFormatContext *s, AVPacket *pkt);

/**
 * Do the SETUP requests for each stream for the chosen
 * lower transport mode.
 * @return 0 on success, <0 on error, 1 if protocol is unavailable
 */
int ff_rivermax_make_setup_request(AVFormatContext *s, const char *host, int port,
                               int lower_transport, const char *real_challenge);

/**
 * Undo the effect of ff_rivermax_make_setup_request, close the
 * transport_priv and rtp_handle fields.
 */
void ff_rivermax_undo_setup(AVFormatContext *s, int send_packets);

/**
 * Open RIVERMAX transport context.
 */
int ff_rivermax_open_transport_ctx(AVFormatContext *s, RIVERMAXStream *rivermax_st);

extern const AVOption ff_rivermax_options[];

#endif /* AVFORMAT_RIVERMAX_H */
