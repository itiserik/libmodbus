/*
 * Copyright © 2001-2011 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <assert.h>

#include "modbus-private.h"

#include "modbus-rtu.h"
#include "modbus-rtu-private.h"

#include "modbus-tcp.h"
#include "modbus-tcp-private.h"

#include "modbus-rtu-over-tcp.h"

int _modbus_set_slave(modbus_t *ctx, int slave);
int _modbus_rtu_build_request_basis(modbus_t *ctx, int function,
                                           int addr, int nb,
                                           uint8_t *req);
int _modbus_rtu_build_response_basis(sft_t *sft, uint8_t *rsp);
int _modbus_rtu_prepare_response_tid(const uint8_t *req, int *req_length);
int _modbus_rtu_send_msg_pre(uint8_t *req, int req_length);
int _modbus_rtu_check_integrity(modbus_t *ctx, uint8_t *msg,
                                const int msg_length);
const modbus_backend_t _modbus_rtu_over_tcp_backend = {
    _MODBUS_BACKEND_TYPE_RTU_OVER_TCP,
    _MODBUS_RTU_HEADER_LENGTH,
    _MODBUS_RTU_CHECKSUM_LENGTH,
    MODBUS_RTU_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_rtu_build_request_basis,
    _modbus_rtu_build_response_basis,
    _modbus_rtu_prepare_response_tid,
    _modbus_rtu_send_msg_pre,
    _modbus_tcp_send,    /* rtu over tcp */
    _modbus_rtu_receive,
    _modbus_tcp_recv,    /* rtu over tcp */
    _modbus_rtu_check_integrity,
    _modbus_rtu_pre_check_confirmation,
    _modbus_tcp_connect, /* rtu over tcp */
    _modbus_tcp_close,   /* rtu over tcp */
    _modbus_tcp_flush,   /* rtu over tcp */
    _modbus_tcp_select,  /* rtu over tcp */
    _modbus_tcp_free
};


const modbus_backend_t _modbus_rtu_over_tcp_pi_backend = {
    _MODBUS_BACKEND_TYPE_RTU_OVER_TCP,
    _MODBUS_RTU_HEADER_LENGTH,
    _MODBUS_RTU_CHECKSUM_LENGTH,
    MODBUS_RTU_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_rtu_build_request_basis,
    _modbus_rtu_build_response_basis,
    _modbus_rtu_prepare_response_tid,
    _modbus_rtu_send_msg_pre,
    _modbus_tcp_send,    /* rtu over tcp */
    _modbus_rtu_receive,
    _modbus_tcp_recv,    /* rtu over tcp */
    _modbus_rtu_check_integrity,
    _modbus_rtu_pre_check_confirmation,
    _modbus_tcp_pi_connect, /* rtu over tcp */
    _modbus_tcp_close,   /* rtu over tcp */
    _modbus_tcp_flush,   /* rtu over tcp */
    _modbus_tcp_select,  /* rtu over tcp */
    _modbus_tcp_free
};


modbus_t* modbus_new_rtu_over_tcp(const char *ip, int port)
{
    modbus_t *ctx;
    modbus_tcp_t *ctx_tcp;
    size_t dest_size;
    size_t ret_size;

#if defined(OS_BSD)
    /* MSG_NOSIGNAL is unsupported on *BSD so we install an ignore
       handler for SIGPIPE. */
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        /* The debug flag can't be set here... */
        fprintf(stderr, "Coud not install SIGPIPE handler.\n");
        return NULL;
    }
#endif

    ctx = (modbus_t *) malloc(sizeof(modbus_t));
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_TCP_SLAVE;

    ctx->backend = &(_modbus_rtu_over_tcp_backend);

    ctx->backend_data = (modbus_tcp_t *) malloc(sizeof(modbus_tcp_t));
    ctx_tcp = (modbus_tcp_t *)ctx->backend_data;

    dest_size = sizeof(char) * 16;
    ret_size = strlcpy(ctx_tcp->ip, ip, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The IP string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The IP string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    ctx_tcp->port = port;

    return ctx;
}

modbus_t* modbus_new_rtu_over_tcp_pi(const char *node, const char *service)
{
    modbus_t *ctx;
    modbus_tcp_pi_t *ctx_tcp_pi;
    size_t dest_size;
    size_t ret_size;

    ctx = (modbus_t *) malloc(sizeof(modbus_t));
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_TCP_SLAVE;

    ctx->backend = &(_modbus_rtu_over_tcp_pi_backend);

    ctx->backend_data = (modbus_tcp_pi_t *) malloc(sizeof(modbus_tcp_pi_t));
    ctx_tcp_pi = (modbus_tcp_pi_t *)ctx->backend_data;

    dest_size = sizeof(char) * _MODBUS_TCP_PI_NODE_LENGTH;
    ret_size = strlcpy(ctx_tcp_pi->node, node, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The node string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The node string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    dest_size = sizeof(char) * _MODBUS_TCP_PI_SERVICE_LENGTH;
    ret_size = strlcpy(ctx_tcp_pi->service, service, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The service string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The service string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    return ctx;
}

