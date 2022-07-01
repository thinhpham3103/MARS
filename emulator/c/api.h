#pragma once

#include "mars.h"

#define MARS_RC_LOCK    3   // MARS is not locked

// MARS API I/O CallBack function
typedef size_t MARS_ApiIoCb (
    void *ctx,
    void *txbuf,
    size_t txlen,
    void *rxbuf,
    ssize_t rxlen);

MARS_RC MARS_ApiInit (
    MARS_ApiIoCb *,
    void *ctx);

MARS_RC MARS_Lock ();
MARS_RC MARS_Unlock ();

