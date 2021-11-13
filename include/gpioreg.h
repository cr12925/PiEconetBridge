#ifndef __ECONETGPIO_REG_H

#define __ECONETGPIO_REG_H

#define PERIBASE 0xFE000000 /* Pi 4 */
//#define PERIBASE 0x3F000000 /* Pi 2, 3, Zero model 2 */
//#define PERIBASE 0x20000000 /* Pi Zero (original version) */

#define GPIO_PERI_BASE (PERIBASE + 0x200000)

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

#define ECONET_GPIO_CLRMASK_DATA        (0xff << (ECONET_GPIO_PIN_DATA))
#define ECONET_GPIO_CLRMASK_ADDR        (0x03 << (ECONET_GPIO_PIN_ADDR))
#define ECONET_GPIO_CLRMASK_RST         (0x01 << ECONET_GPIO_PIN_RST)
#define ECONET_GPIO_CLRMASK_IRQ         (0x01 << ECONET_GPIO_PIN_IRQ)
#define ECONET_GPIO_CLRMASK_CS          (0x01 << ECONET_GPIO_PIN_CS)
#define ECONET_GPIO_CLRMASK_CLK         (0x01 << ECONET_GPIO_PIN_CLK)
#define ECONET_GPIO_CLRMASK_RW          (0x01 << ECONET_GPIO_PIN_RW)
#define ECONET_GPIO_CLRMASK_BUSY         (0x01 << ECONET_GPIO_PIN_BUSY)

#define ECONET_GPIO_CLOCKSPEED	1000000	/* 1 Mhz clock. Slower than the Beeb but easier to manage */
//#define ECONET_GPIO_CLOCKIDIV (750 << 12)
#define ECONET_GPIO_CLOCKIDIV (500 << 12) // Broadly working at 700
#define ECONET_GPIO_CLOCKFDIV (0 & 0xfff)
#define ECONET_GPIO_CLK_ALT_FUNCTION 0x04 /* ALT0 for the pin we're using. Change this by reference to the ARM SOC reference manual if your clock is on a pin which doesn't want FSELn set to 100 for the CLock function */
#define GPSEL0 0x00
#define GPSET0 0x07
#define GPCLR0 0x0a
#define GPLEV0 0x0d

// IRQ debug
#define GPREN0 19
#define GPFEN0 22
#define GPHEN0 25
#define GPLEN0 28


/* Pin numbering index */

enum econet_gpio_pin_index {
        EGP_D0 = 0,
        EGP_D1,
        EGP_D2,
        EGP_D3,
        EGP_D4,
        EGP_D5,
        EGP_D6,
        EGP_D7,
        EGP_A0,
        EGP_A1,
        EGP_RST,
        EGP_CS,
        EGP_CLK,
        EGP_RW,
        EGP_DIR,
        EGP_IRQ,
	EGP_CSRETURN };

#endif

