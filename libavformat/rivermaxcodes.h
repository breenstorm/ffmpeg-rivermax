/*
 * RIVERMAX definitions
 * copyright (c) 2002 Fabrice Bellard
 * copyright (c) 2014 Samsung Electronics. All rights reserved.
 *     @Author: Reynaldo H. Verdejo Pinochet <r.verdejo@sisa.samsung.com>
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

#ifndef AVFORMAT_RIVERMAXCODES_H
#define AVFORMAT_RIVERMAXCODES_H

#include "libavutil/common.h"
#include "libavformat/http.h"

/** RIVERMAX handling */
enum RIVERMAXStatusCode {
RIVERMAX_STATUS_CONTINUE             =100,
RIVERMAX_STATUS_OK                   =200,
RIVERMAX_STATUS_CREATED              =201,
RIVERMAX_STATUS_LOW_ON_STORAGE_SPACE =250,
RIVERMAX_STATUS_MULTIPLE_CHOICES     =300,
RIVERMAX_STATUS_MOVED_PERMANENTLY    =301,
RIVERMAX_STATUS_MOVED_TEMPORARILY    =302,
RIVERMAX_STATUS_SEE_OTHER            =303,
RIVERMAX_STATUS_NOT_MODIFIED         =304,
RIVERMAX_STATUS_USE_PROXY            =305,
RIVERMAX_STATUS_BAD_REQUEST          =400,
RIVERMAX_STATUS_UNAUTHORIZED         =401,
RIVERMAX_STATUS_PAYMENT_REQUIRED     =402,
RIVERMAX_STATUS_FORBIDDEN            =403,
RIVERMAX_STATUS_NOT_FOUND            =404,
RIVERMAX_STATUS_METHOD               =405,
RIVERMAX_STATUS_NOT_ACCEPTABLE       =406,
RIVERMAX_STATUS_PROXY_AUTH_REQUIRED  =407,
RIVERMAX_STATUS_REQ_TIME_OUT         =408,
RIVERMAX_STATUS_GONE                 =410,
RIVERMAX_STATUS_LENGTH_REQUIRED      =411,
RIVERMAX_STATUS_PRECONDITION_FAILED  =412,
RIVERMAX_STATUS_REQ_ENTITY_2LARGE    =413,
RIVERMAX_STATUS_REQ_URI_2LARGE       =414,
RIVERMAX_STATUS_UNSUPPORTED_MTYPE    =415,
RIVERMAX_STATUS_PARAM_NOT_UNDERSTOOD =451,
RIVERMAX_STATUS_CONFERENCE_NOT_FOUND =452,
RIVERMAX_STATUS_BANDWIDTH            =453,
RIVERMAX_STATUS_SESSION              =454,
RIVERMAX_STATUS_STATE                =455,
RIVERMAX_STATUS_INVALID_HEADER_FIELD =456,
RIVERMAX_STATUS_INVALID_RANGE        =457,
RIVERMAX_STATUS_RONLY_PARAMETER      =458,
RIVERMAX_STATUS_AGGREGATE            =459,
RIVERMAX_STATUS_ONLY_AGGREGATE       =460,
RIVERMAX_STATUS_TRANSPORT            =461,
RIVERMAX_STATUS_UNREACHABLE          =462,
RIVERMAX_STATUS_INTERNAL             =500,
RIVERMAX_STATUS_NOT_IMPLEMENTED      =501,
RIVERMAX_STATUS_BAD_GATEWAY          =502,
RIVERMAX_STATUS_SERVICE              =503,
RIVERMAX_STATUS_GATEWAY_TIME_OUT     =504,
RIVERMAX_STATUS_VERSION              =505,
RIVERMAX_STATUS_UNSUPPORTED_OPTION   =551,
};

static const av_unused char * const rivermax_status_strings[] = {
[RIVERMAX_STATUS_CONTINUE]               ="Continue",
[RIVERMAX_STATUS_OK]                     ="OK",
[RIVERMAX_STATUS_CREATED]                ="Created",
[RIVERMAX_STATUS_LOW_ON_STORAGE_SPACE]   ="Low on Storage Space",
[RIVERMAX_STATUS_MULTIPLE_CHOICES]       ="Multiple Choices",
[RIVERMAX_STATUS_MOVED_PERMANENTLY]      ="Moved Permanently",
[RIVERMAX_STATUS_MOVED_TEMPORARILY]      ="Moved Temporarily",
[RIVERMAX_STATUS_SEE_OTHER]              ="See Other",
[RIVERMAX_STATUS_NOT_MODIFIED]           ="Not Modified",
[RIVERMAX_STATUS_USE_PROXY]              ="Use Proxy",
[RIVERMAX_STATUS_BAD_REQUEST]            ="Bad Request",
[RIVERMAX_STATUS_UNAUTHORIZED]           ="Unauthorized",
[RIVERMAX_STATUS_PAYMENT_REQUIRED]       ="Payment Required",
[RIVERMAX_STATUS_FORBIDDEN]              ="Forbidden",
[RIVERMAX_STATUS_NOT_FOUND]              ="Not Found",
[RIVERMAX_STATUS_METHOD]                 ="Method Not Allowed",
[RIVERMAX_STATUS_NOT_ACCEPTABLE]         ="Not Acceptable",
[RIVERMAX_STATUS_PROXY_AUTH_REQUIRED]    ="Proxy Authentication Required",
[RIVERMAX_STATUS_REQ_TIME_OUT]           ="Request Time-out",
[RIVERMAX_STATUS_GONE]                   ="Gone",
[RIVERMAX_STATUS_LENGTH_REQUIRED]        ="Length Required",
[RIVERMAX_STATUS_PRECONDITION_FAILED]    ="Precondition Failed",
[RIVERMAX_STATUS_REQ_ENTITY_2LARGE]      ="Request Entity Too Large",
[RIVERMAX_STATUS_REQ_URI_2LARGE]         ="Request URI Too Large",
[RIVERMAX_STATUS_UNSUPPORTED_MTYPE]      ="Unsupported Media Type",
[RIVERMAX_STATUS_PARAM_NOT_UNDERSTOOD]   ="Parameter Not Understood",
[RIVERMAX_STATUS_CONFERENCE_NOT_FOUND]   ="Conference Not Found",
[RIVERMAX_STATUS_BANDWIDTH]              ="Not Enough Bandwidth",
[RIVERMAX_STATUS_SESSION]                ="Session Not Found",
[RIVERMAX_STATUS_STATE]                  ="Method Not Valid in This State",
[RIVERMAX_STATUS_INVALID_HEADER_FIELD]   ="Header Field Not Valid for Resource",
[RIVERMAX_STATUS_INVALID_RANGE]          ="Invalid Range",
[RIVERMAX_STATUS_RONLY_PARAMETER]        ="Parameter Is Read-Only",
[RIVERMAX_STATUS_AGGREGATE]              ="Aggregate Operation no Allowed",
[RIVERMAX_STATUS_ONLY_AGGREGATE]         ="Only Aggregate Operation Allowed",
[RIVERMAX_STATUS_TRANSPORT]              ="Unsupported Transport",
[RIVERMAX_STATUS_UNREACHABLE]            ="Destination Unreachable",
[RIVERMAX_STATUS_INTERNAL]               ="Internal Server Error",
[RIVERMAX_STATUS_NOT_IMPLEMENTED]        ="Not Implemented",
[RIVERMAX_STATUS_BAD_GATEWAY]            ="Bad Gateway",
[RIVERMAX_STATUS_SERVICE]                ="Service Unavailable",
[RIVERMAX_STATUS_GATEWAY_TIME_OUT]       ="Gateway Time-out",
[RIVERMAX_STATUS_VERSION]                ="RIVERMAX Version not Supported",
[RIVERMAX_STATUS_UNSUPPORTED_OPTION]     ="Option not supported",
};

#define RIVERMAX_STATUS_CODE2STRING(x) (\
x >= 100 && x < FF_ARRAY_ELEMS(rivermax_status_strings) && rivermax_status_strings[x] \
)? rivermax_status_strings[x] : NULL

enum RIVERMAXMethod {
    DESCRIBE,
    ANNOUNCE,
    OPTIONS,
    SETUP,
    PLAY,
    PAUSE,
    TEARDOWN,
    GET_PARAMETER,
    SET_PARAMETER,
    REDIRECT,
    RECORD,
    UNKNOWN = -1,
};

static inline int ff_rivermax_averror(enum RIVERMAXStatusCode status_code, int default_averror)
{
    return ff_http_averror(status_code, default_averror);
}

#endif /* AVFORMAT_RIVERMAXCODES_H */
