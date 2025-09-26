/**
 * @file supplicant_procedures.h
 * @brief Supplicant state machine procedures
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEAP Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.4
 **/

#ifndef _SUPPLICANT_PROCEDURES_H
#define _SUPPLICANT_PROCEDURES_H

//Dependencies
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Supplicant related functions
void supplicantTxStart(SupplicantContext *context);
void supplicantTxLogoff(SupplicantContext *context);

void supplicantAbortSupp(SupplicantContext *context);
void supplicantGetSuppRsp(SupplicantContext *context);
void supplicantTxSuppRsp(SupplicantContext *context);

void supplicantDecrementTimer(uint_t *x);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
