/*
  (c) 2020 Chris Royle
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef __ECONETGPIOCHIPCTRL_H__

#define __ECONETGPIOCHIPCTRL_H__

#include "gpioreg.h"

/* Functions to read/write the data bus */

void econet_set_dir(short); /* This calls econet_set_rw(), but also changes the directions of the data bus lines */
unsigned char econet_write_bus(unsigned char);
unsigned char econet_write_bus_slow(unsigned char);
unsigned char econet_read_bus(void);
void econet_write_cr(short, unsigned char);
void econet_write_cr_long(short, unsigned char);
unsigned char econet_read_sr(short);
void econet_gpio_release(void);

void econet_reset(void);
void econet_flagfill(void);

#define INP_GPIO(g) *(GPIO_PORT+((g)/10)) &= ~(7<<(((g)%10)*3))
#define OUT_GPIO(g) *(GPIO_PORT+((g)/10)) |=  (1<<(((g)%10)*3))
#define SET_GPIO_ALT(g,a) *(GPIO_PORT+(((g)/10))) |= (((a)<=3?(a)+4:(a)==4?3:2)<<(((g)%10)*3))

#define econet_gpio_pin(p) 	(readl(GPIO_PORT + GPLEV0) & (1 << p))

#define econet_isbusy()		(econet_gpio_pin(ECONET_GPIO_PIN_BUSY))
	
/* Low level chip control functions */

#define econet_set_addr(x,y)	gpioset_value = (((x) << (ECONET_GPIO_PIN_ADDR + 1)) | ((y) << (ECONET_GPIO_PIN_ADDR))); \
				writel(gpioset_value, GPIO_PORT + GPSET0); \
				writel(((~gpioset_value) & ECONET_GPIO_CLRMASK_ADDR), GPIO_PORT + GPCLR0); \
				barrier()

#define econet_set_rw(x)	if (x)	writel(ECONET_GPIO_CLRMASK_RW, (GPIO_PORT + GPSET0)); \
				else	writel(ECONET_GPIO_CLRMASK_RW, (GPIO_PORT + GPCLR0))

#define econet_set_datadir_in	for (gpioset_value = ECONET_GPIO_PIN_DATA; gpioset_value < (ECONET_GPIO_PIN_DATA + 8); gpioset_value++) \
				{ \
					*(GPIO_PORT + GPSEL0 + (gpioset_value/10)) &= (7<<((gpioset_value % 10) * 3)); \
				}
#define econet_set_datadir_out	for (gpioset_value = ECONET_GPIO_PIN_DATA; gpioset_value < (ECONET_GPIO_PIN_DATA + 8); gpioset_value++) \
				{ \
					*(GPIO_PORT + GPSEL0 + (gpioset_value/10)) |= (7<<((gpioset_value %10) * 3)); \
				}
#define econet_set_cs(x)	if (x)	writel(ECONET_GPIO_CLRMASK_CS, (GPIO_PORT + (econet_data->hwver < 2 ? GPSET0 : GPCLR0))); \
				else	writel(ECONET_GPIO_CLRMASK_CS, (GPIO_PORT + (econet_data->hwver < 2 ? GPCLR0 : GPSET0)))

#define econet_set_rst(x)	if (x)	writel(ECONET_GPIO_CLRMASK_RST, (GPIO_PORT + GPSET0)); \
				else	writel(ECONET_GPIO_CLRMASK_RST, (GPIO_PORT + GPCLR0))


#define econet_ndelay(t)	{ \
					u64 p; \
					\
					p = ktime_get_ns() + t; \
					while (ktime_get_ns() < p);\
				}

#ifndef ECONET_NO_NDELAY
	#define econet_wait_pin_low(p,t)	{ \
					u64 timer; \
					\
					timer = ktime_get_ns() + t; \
					while ( (ktime_get_ns() < timer) && (readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)));\
				}
#else
	#define econet_wait_pin_low(p,t)	while (readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN))
#endif
					
/* Note that there are two assignments to sr2 here. The first is the historical one. The second is because we discovered that SR2Q on S1 did not go high when, for example, /DCD alone was set in SR2, so we now read both registers. Old code left so we don't lose it */
#define econet_get_sr()	{ \
		sr1 = econet_read_sr(1); \
		sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : ((sr1 & ECONET_GPIO_S1_RDA) >> 7); \
		sr2 = econet_read_sr(2); \
		econet_data->clock = (sr2 & ECONET_GPIO_S2_DCD) ? 0 : 1; \
		}

#endif

#define econet_set_chipstate(x) { \
	econet_data->mode = (x); \
	/* printk (KERN_INFO "ECONET-GPIO: econet_set_chipstate(%d)\n", (x)); */ \
}


/* Control and status reg indexes */
#define ECONET_GPIO_CR1 1
#define ECONET_GPIO_CR2 2
#define ECONET_GPIO_CR3 3
#define ECONET_GPIO_CR4 4
#define ECONET_GPIO_SR1 1
#define ECONET_GPIO_SR2 2

/* Control Register 1 */

#define ECONET_GPIO_C1_AC 0x01 /* Address control - selects whether writing CR2 v CR3, or CR4 v Frame Terminate Byte */
#define ECONET_GPIO_C1_RINT 0x02 /* Receiver interrupt enable */
#define ECONET_GPIO_C1_TINT 0x04 /* Transmitter interrupt enable */
#define ECONET_GPIO_C1_RDSR 0x08 /* See data sheet */
#define ECONET_GPIO_C1_TDSR 0x10 /* See data sheet */
#define ECONET_GPIO_C1_RX_DISC 0x20 /* Receiver discontinue - dump frame */
#define ECONET_GPIO_C1_RX_RESET 0x40 /* RX Reset */
#define ECONET_GPIO_C1_TX_RESET 0x80 /* TX Reset */

/* Control Register 2 */

#define ECONET_GPIO_C2_PSE 0x01 /* Prioritised status enabled - status registers not suppressed by other status bits */
#define ECONET_GPIO_C2_2BYTES 0x02 /* Two-byte transfers instead of 1-byte through the FIFO on TDSR */
#define ECONET_GPIO_C2_FLAGIDLE 0x04 /* Flag / Mark Idle - used to turn on flag fill */
#define ECONET_GPIO_C2_FC 0x08 /* 1 = TDRA Status bit means Frame Complete */
#define ECONET_GPIO_C2_TXLAST 0x10 /* Set this after loading last byte as one of the two ways of signalling it is the last byte of a frame */
#define ECONET_GPIO_C2_CLR_RX_STATUS 0x20 /* Reset receiver status bits in SR1 & SR2 - not AP and RDA */
#define ECONET_GPIO_C2_CLR_TX_STATUS 0x40 /* Reset transmitter status bits in SR1 except TDRA */
#define ECONET_GPIO_C2_RTS 0x80 /* RTS control */

/* Control Register 3 - Usually set to &00 at all times */
/* Accessible only when CR1_AC = 1 and RS1RS0 = 01 */
#define C3_LCF 0x01 /* Logical Control Field Select - Enables the LCF in frames; 0 means no LCF expected, which is how Econet works */
#define ECONET_GPIO_C3_ECF 0x02 /* Extended Control Field Select - extends LCF to 16 bits */
#define ECONET_GPIO_C3_AEX 0x04 /* Address expand mode - 0 means 8 bit address, 1 means that if bit 0 of an address octet is 0 then address extended by one octet */
#define ECONET_GPIO_C3_FDSE 0x10 /* Flag Detect status enable - enables FD status bit in SR1. Accompanied by IRQ if RINT (RIE) is enabled */
#define ECONET_GPIO_C3_LOOP 0x20 /* Loop Mode Enable - not used by Econet */
#define ECONET_GPIO_C3_TST 0x40 /* Self-test - connects Tx to Rx internally. In Loop-mode, does something totally different. */
#define ECONET_GPIO_C3_DTR 0x80 /* Controls BarDTR output. In Loop mode, does something totally different. */

/* Control Register 4 - Usually set to 0x1E (all words 8 bit, everything else off) */
/* Accessible only when RS1RS0=11 and CR1_AC=1 */
#define C4_DBLFLAG 0x01 /* Double Flag enable - if set to 0, closing flag of one frame can be opening flag of next. Otherwise extra flag sent */
/* Transmit word length control at b1, b2 */
#define ECONET_GPIO_C4_TX_WORDLEN_5 0x00 /* Set Transmit word length 5 bits  */
#define ECONET_GPIO_C4_TX_WORDLEN_6 0x02 /* 6 */
#define ECONET_GPIO_C4_TX_WORDLEN_7 0x04 /* 7 */
#define ECONET_GPIO_C4_TX_WORDLEN_8 0x06 /* 8 */
/* Receiver word length in b3, b4 */
#define ECONET_GPIO_C4_RX_WORDLEN_5 0x00
#define ECONET_GPIO_C4_RX_WORDLEN_6 0x08
#define ECONET_GPIO_C4_RX_WORDLEN_7 0x10
#define ECONET_GPIO_C4_RX_WORDLEN_8 0x18
/* CR4 other flags */
#define ECONET_GPIO_C4_TX_ABORT 0x20 /* Abort existing frame transmit */
#define ECONET_GPIO_C4_TX_ABORT_EXT 0x40 /* Abort code sent on abort is extended to at least 16 1s */
#define ECONET_GPIO_C4_TX_NRZI 0x80 /* 0 = NRZ, 1 = NRZI */

/* Status registers */

#define ECONET_GPIO_S1_RDA 0x01 /* Received data available */
#define ECONET_GPIO_S1_S2RQ 0x02 /* Set if any of the status bits in SR2 is set */
#define ECONET_GPIO_S1_LOOP 0x04 /* 1 = Loop Mode enabled */
#define ECONET_GPIO_S1_FLAG 0x08 /* Flag detected - if this is enabled by CR3_FDSE */
#define ECONET_GPIO_S1_CTS 0x10 /* BarCTS positive transition stored here. Causes IRQ if receiver interrupt enabled */
#define ECONET_GPIO_S1_UNDERRUN 0x20 /* Transmitter underrun - FIFO ran out of data. Cleared by CR2_CLR_TX_STATUS */
#define ECONET_GPIO_S1_TDRA 0x40 /* If CR2_TDRA=1 then this means Frame Complete. Otherwise indicates Tx FIFO available */
#define ECONET_GPIO_S1_IRQ 0x80 /* Interrupt generated */

#define ECONET_GPIO_S2_AP 0x01 /* Address present - in Econet-world, first byte of frame received*/
#define ECONET_GPIO_S2_VALID 0x02 /* Frame complete without error - set when last byte of frame put in Rx FIFO */
#define ECONET_GPIO_S2_RX_IDLE 0x04 /* 15 1's received on the wire. Can cause interrupt if enabled. Reset with CR2_CLR_RX_STATUS */
#define ECONET_GPIO_S2_RX_ABORT 0x08 /* Abort received  - can be cleared with CR2_CLR_RX_STATUS */
#define ECONET_GPIO_S2_ERR 0x10 /* Frame CRC error on receive. Exclusive to SR2_VALID */
#define ECONET_GPIO_S2_DCD 0x20 /* BarDCD High. Cleared with CR2_CLR_RX_STATUS */
#define ECONET_GPIO_S2_OVERRUN 0x40 /* Rx FIFO Full on receive */
#define ECONET_GPIO_S2_RDA 0x80 /* Receiver data available - Rx FIFO has data for us */

/* Particular values to put in registers to do certain things */

#define C1_READ (ECONET_GPIO_C1_RINT | ECONET_GPIO_C1_TX_RESET)
//#define C2_READ (ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_2BYTES)
#define C2_READ (ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_FLAGIDLE)
#define C3_READ 0x00
#define C4_READ (ECONET_GPIO_C4_TX_WORDLEN_8 | ECONET_GPIO_C4_RX_WORDLEN_8)

/* Write init phase 1 is to clear the status flags - see &86D1 in the ANFS4.25 code*/
//#define C2_WRITE_INIT1 (ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_2BYTES | ECONET_GPIO_C2_FLAGIDLE)
#define C2_WRITE_INIT1 (ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE)

/* Write init phase 2 is to set RTS in CR2, then RX discontinue & enable TX IRQ on CR1 */
#define C1_WRITE_INIT2 (ECONET_GPIO_C1_RX_RESET | ECONET_GPIO_C1_TINT)

/* Second phase write setup */
//#define C2_WRITE_INIT2 (ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_RTS | ECONET_GPIO_C2_2BYTES)
#define C2_WRITE_INIT2 (ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS | ECONET_GPIO_C2_RTS)

/* End of frame on transmit */
//#define C2_WRITE_EOF (ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_TXLAST | ECONET_GPIO_C2_FC | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_2BYTES | ECONET_GPIO_C2_PSE)
#define C2_WRITE_EOF (ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_TXLAST | ECONET_GPIO_C2_FC | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_PSE)
