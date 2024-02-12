/**
 * @file eap.h
 * @brief EAP (Extensible Authentication Protocol)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.0
 **/

#ifndef _EAP_H
#define _EAP_H

//Dependencies
#include "eap_config.h"
#include "core/net.h"
#include "core/crypto.h"


/*
 * CycloneEAP Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneEAP Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneEAP Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneEAP Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneEAP Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_EAP_VERSION_STRING "2.4.0"
//Major version
#define CYCLONE_EAP_MAJOR_VERSION 2
//Minor version
#define CYCLONE_EAP_MINOR_VERSION 4
//Revision number
#define CYCLONE_EAP_REV_NUMBER 0

#endif
