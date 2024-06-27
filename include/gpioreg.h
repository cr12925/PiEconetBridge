#ifndef __ECONETGPIO_REG_H

#define __ECONETGPIO_REG_H

#define GPIO_PERI_BASE ((econet_data->peribase) + 0x200000)

/* GPIO PINS - Broadcom numbering */

#define ECONET_GPIO_PIN_DATA    20      /* This has to be pin 0 of 0-7 (8 pins) CONSECUTIVE */
#define ECONET_GPIO_PIN_ADDR    12      /* Two pins Consecutive - RS0, RS1 to card  - RS0 is the lower numbered pin */
#define ECONET_GPIO_PIN_RST     19      /* /RST to card */
#define ECONET_GPIO_PIN_IRQ     17      /* /IRQ from card */
#define ECONET_GPIO_PIN_CS      5       /* /CS to card */
#define ECONET_GPIO_PIN_CLK     4       /* Clock to card. We set this manually. Just here for reference. */
#define ECONET_GPIO_PIN_RW      6       /* /RW to card */
#define ECONET_GPIO_PIN_BUSY     16      /* v.2 hardware busy line */
#define ECONET_GPIO_PIN_CSRETURN	18	/* Pin on which we read /CS as fed to the 68B54 after the D-Type flipflop */
#define ECONET_GPIO_PIN_WIRECLK		ECONET_GPIO_PIN_CSRETURN /* On v2c boards, this pin is used to output a PWM waveform to source a clock for the wire */
#define ECONET_GPIO_PIN_LED_WRITE	11 /* Drives the write LED */
#define ECONET_GPIO_PIN_LED_READ	8 /* Drives the read LED */
#define ECONET_GPIO_PIN_NET_CLOCK	ECONET_GPIO_PIN_CSRETURN	/* PWM output for network clock on v2r3 board */

#define ECONET_GPIO_CLRMASK_DATA        (0xff << (ECONET_GPIO_PIN_DATA))
#define ECONET_GPIO_CLRMASK_ADDR        (0x03 << (ECONET_GPIO_PIN_ADDR))
#define ECONET_GPIO_CLRMASK_RST         (0x01 << ECONET_GPIO_PIN_RST)
#define ECONET_GPIO_CLRMASK_IRQ         (0x01 << ECONET_GPIO_PIN_IRQ)
#define ECONET_GPIO_CLRMASK_CS          (0x01 << ECONET_GPIO_PIN_CS)
#define ECONET_GPIO_CLRMASK_CLK         (0x01 << ECONET_GPIO_PIN_CLK)
#define ECONET_GPIO_CLRMASK_RW          (0x01 << ECONET_GPIO_PIN_RW)
#define ECONET_GPIO_CLRMASK_BUSY         (0x01 << ECONET_GPIO_PIN_BUSY)

/* 
 * BCM Peripheral addresses for GPIO 
 */

#define NGPSET0 (GPIO_PORT + 0x1c)
#define NGPCLR0 (GPIO_PORT + 0x28)
#define NGPLEV0 (GPIO_PORT + 0x34)
#define NGPFSEL0 (GPIO_PORT + 0x00)
#define NGPFSEL2 (GPIO_PORT + 0x08)

#endif

