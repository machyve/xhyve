/*-
 * Copyright (c) 2012 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#pragma once

#include <stdint.h>

#define SCI_INT 9

#define SMI_CMD 0xb2
#define BHYVE_ACPI_ENABLE 0xa0
#define BHYVE_ACPI_DISABLE 0xa1

#define PM1A_EVT_ADDR 0x400
#define PM1A_EVT_ADDR2 0x402
#define PM1A_CNT_ADDR 0x404

#define IO_PMTMR 0x408 /* 4-byte i/o port for the timer */

extern char* asl_compiler_path;

typedef int (*acpi_build_func_t)(int ncpu);
typedef void (*dsdt_line_func_t)(const char *fmt, ...);
typedef void (*dsdt_fixed_ioport_func_t)(uint16_t iobase, uint16_t length);
typedef void (*dsdt_fixed_irq_func_t)(uint8_t irq);
typedef void (*dsdt_fixed_mem32_func_t)(uint32_t base, uint32_t length);
typedef void (*dsdt_indent_func_t)(int levels);
typedef void (*dsdt_unindent_func_t)(int levels);
typedef void (*dsdt_fixup_func_t)(int bus, uint16_t iobase, uint16_t iolimit, uint32_t membase32, uint32_t memlimit32,
		uint64_t membase64, uint64_t memlimit64);

struct acpi_ops_t {
	acpi_build_func_t acpi_build;
	dsdt_line_func_t dsdt_line;
	dsdt_fixed_ioport_func_t dsdt_fixed_ioport;
	dsdt_fixed_irq_func_t dsdt_fixed_irq;
	dsdt_fixed_mem32_func_t dsdt_fixed_mem32;
	dsdt_indent_func_t dsdt_indent;
	dsdt_unindent_func_t dsdt_unindent;
	dsdt_fixup_func_t dsdt_fixup;
};

extern struct acpi_ops_t acpi_ops;
extern struct acpi_ops_t acpi_ops_compile;
extern struct acpi_ops_t acpi_ops_prebuilt_aml;

void acpi_init(void);
void sci_init(void);
