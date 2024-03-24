#ifndef __ECONETGPIO_REG_H

#define __ECONETGPIO_REG_H

//#define PERIBASE 0xFE000000 /* Pi 4 */
//#define PERIBASE 0x3F000000 /* Pi 2, 3, Zero model 2 */
//#define PERIBASE 0x20000000 /* Pi Zero (original version) */

//#define GPIO_PERI_BASE (PERIBASE + 0x200000)
#define GPIO_PERI_BASE ((econet_data->peribase) + 0x200000)
#define CLOCK_PERI_BASE ((econet_data->peribase) + 0x101000)
#define PWM_PERI_BASE ((econet_data->peribase) + 0x20C000)

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

// GP CLK 0
#define ECONET_GPIO_CMCTL 28 /* The offset within Clock base address to the Clock Manager Control for the pin we are using - here, BCM4 */

// PWM CLK
#define ECONET_GPIO_PWM_CLKCTL 40 // PWM Control within the clock space 
#define ECONET_GPIO_PWM_CLKDIV 41 // PWM Div within the clock space 

#define ECONET_GPIO_CLOCKPASSWD 0x5A000000
#define ECONET_GPIO_CLOCKSRC 0x06 /* PLLD */
#define ECONET_GPIO_CLOCKDISABLE (ECONET_GPIO_CLOCKPASSWD | 0x00000020)
#define ECONET_GPIO_CLOCKSOURCEPLLD (ECONET_GPIO_CLOCKPASSWD | ECONET_GPIO_CLOCKSRC)
#define ECONET_GPIO_CLOCKENABLE (ECONET_GPIO_CLOCKPASSWD | 0x00000010 | ECONET_GPIO_CLOCKSRC)
#define ECONET_GPIO_CLOCKIDIV (62) /* We use PLLD, which is a constant 500 Mhz source, so we divide by 62.5 (hence FDIV is 512 because the divisor is (IDIV + (FDIV/1024)) )  We want 8MHz which gets divided on the board. */
#define ECONET_GPIO_CLOCKFDIV (512)
#define ECONET_GPIO_CLOCKDIVSET (ECONET_GPIO_CLOCKPASSWD | (ECONET_GPIO_CLOCKIDIV << 12) | ECONET_GPIO_CLOCKFDIV)
#define ECONET_GPIO_CLOCKDIVFAST (ECONET_GPIO_CLOCKPASSWD | (93 << 12) | (768)) // Some variants run PLLD at 750MHz not 500MHz - so this larger divider is the failsafe default to avoid driving the 68B54 too quickly
#define ECONET_GPIO_CLK_ALT_FUNCTION 0x04 /* ALT0 for the pin we're using. Change this by reference to the ARM SOC reference manual if your clock is on a pin which doesn't want FSELn set to 100 for the CLock function */
#define GPSEL0 0x00
#define GPSET0 0x07
#define GPCLR0 0x0a
#define GPLEV0 0x0d

// PWM defines (with thanks to the authors of PiGPIO)
#define PWM_CTL      0
#define PWM_STA      1
#define PWM_DMAC     2
#define PWM_RNG1     4
#define PWM_DAT1     5
#define PWM_FIFO     6
#define PWM_RNG2     8
#define PWM_DAT2     9

#define PWM_CTL_MSEN2 (1<<15)
#define PWM_CTL_PWEN2 (1<<8)
#define PWM_CTL_MSEN1 (1<<7)
#define PWM_CTL_CLRF1 (1<<6)
#define PWM_CTL_USEF1 (1<<5)
#define PWM_CTL_MODE1 (1<<1)
#define PWM_CTL_PWEN1 (1<<0)

#define PWM_DMAC_ENAB      (1 <<31)
#define PWM_DMAC_PANIC(x) ((x)<< 8)
#define PWM_DMAC_DREQ(x)   (x)

// IRQ debug
#define GPREN0 19
#define GPFEN0 22
#define GPHEN0 25
#define GPLEN0 28

#endif

