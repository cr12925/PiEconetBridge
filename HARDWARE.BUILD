How to build the interface hardware on a breadboard
---------------------------------------------------

These instructions are provided subject to the same terms as the rest of the
code and diagrams in the GitHub repository cr12925/PiEconetBridge.

Specifically:

/*
  (c) 2021 Chris Royle
    These instructions are free: you can redistribute them and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    The instructions are distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with these instructions.  If not, see <https://www.gnu.org/licenses/>.
*/

Components list
---------------

You will need:

1 x large breadboard - three 'columns' and about twice as long as the ADF10
    adapter

1 x Acorn ADF10 adapter (Master 128 Econet board) or equivalent

1 x Breadboard friendly DIN socket (5-pin, 180 degrees). More if you want more
    sockets. (I have in the past built a terminator onto the last socket in the
    chain on my breadboard and it has worked - but these instructions do not
    include that.)

1 x GPIO extension board (see photo - takes the 40-pin GPIO connector via ribbon
cable to a T-shaped board on the breadboard)

2 x 74LVC245AN level shifters (run at 3.3V)

1 x 74LS74 D-Type flip flop (5V part)

1 x 74LS31N delay line (5V part)

1 x 5V Crystal oscillator 1MHz (faster if you want to change the wait time in
    the code). E.g. a 4-pin Epson 5V part.

5 x 104 capacitors (100nF)

Many x various lengths of breadboard wire

Before proceeding, read the rest of these instructions to ensure you understand 
how the parts will be used in case there is any confusion over what you need
to buy.

NOTE: for reasons which are presently unclear, this only really works on a
Pi 4B as the host. Pi Zero does very little; Pi 3B tends to produce 
repeated bytes in received packets. It is on the list to investigate and
fix!


Stage 1 - Install the ADF10 on the breadboard
---------------------------------------------

Install in top left corner such that the 17-pin connector is on the right, and 
the 5-pin connector is on the left, AND such that the 5-pin connector has at 
least one column of pinholes available before the side of the board (otherwise 
you'll not be able to connect anything to it). In terms of vertical positioning,
either put the last of the long row of pins in the last hole before the end of 
the board, or leave one space. For reasons that will become clear later, no
further is advised.

Stage 2 - Install DIN sockets bottom left of breadboard & connect to ADF10
--------------------------------------------------------------------------

Install one or more DIN sockets on the left hand edge of the breadboard.

The output pins on the ADF10 do not run in the same order as the input pins to
the DIN sockets :(

On the following arrangement, the pins connect as follows:

ADF10 from top left of board		DIN socket from LEFT to RIGHT, 
					looking at REAR of socket
					(DIN numbering in brackets)

5 (Clock-)				5 (3)
4 (Clock+)				4 (5)
3 (Ground)				3 - Centre - Ground (2)
2 (Data-)				2 (4)
1 (Data+)				1 (1)

If you have more than one socket, connect the sockets in parallel. You will
need a terminator either in the last socket or on the board somewhere near it.
A circuit diagram and parts list can be found (at the time of writing), here:
https://www.retro-kit.co.uk/page.cfm/content/Passive-Econet-Terminators/

I acknowledge the Copyright of whoever's website that is. It is not my work. 
I am grateful to them.

Stage 3 - Position the GPIO expansion module
--------------------------------------------

Bottom right of the board - diagonally opposite the ADF10, straddling the 
centre break (fairly obviously!).

Do not connect ribbon cable to Pi as yet!

Stage 4 - Providing power
-------------------------

Your breadboard should have at least two power rails (blue -ve, red +ve).

Connect the 5V from the GPIO expansion module to one +ve power rail.

Connect 3.3V from the GPIO expansion module to the other +ve power rail. 
Obviously not the same power rail as the 5V.

Connect two separate ground outlets from the GPIO expansion module to the -ve

Stage 5 - Position the ICs on the breadboard
--------------------------------------------

There are five ICs to place on the breadboard. Start with the two 74LVC245AN
level shifters.

Position the two levelshifters in the top right corner of the breadboard, 
straddling the centre gap, as follows:

- Both should have their 'notch' towards the end of the breadboard where the
  ADF10 is. (In fact that is so of ALL the ICs to be installed.)

- One should be positioned so as to leave at least one row of pinholes between
  its notch and the end of the board. This is the *data bus level shifter*. 
  This switches direction depending on whether we are reading or writing from/to  the ADLC. The precise vertical position of this chip should be such that it
  starts precisely 2 rows further in from the end of the breadboard than
  the ADF10's first pin in the long set. (This allows you to have a straight 
  run across the board for the data bus.)

- The other should be in line with it, with at least 5 rows of pinholes between
  the bottom of the first and the notch end of the second. This is the *return
  level shifter*. It only ever carries two signals (IRQ & /CS return) from the
  Econet side of things back to the Pi.

Next, the clock IC:

- Notch towards the end of the breadboard where the ADF10 is

- Position in centre column of the breadboard (mine has 3 columns), a few rows
  below the bottom of the ADF10 (i.e. the end of the ADF10 away from the end of
  the breadboard).

Next the delay line:

- Position straddling the centre of the centre column, leaving 4-5 holes
  between the un-notched end of the clock chip and the notched end of the delay
  line you are fitting.

Last, the D-Type flip-flop

- Position straddling the centre of the centre column, leaving 4-5 holes
  between the un-notched end of the delay line and the notched end of the
  D-Type you are fitting.

Stage 6 - Provide power to each chip & the ADF10
------------------------------------------------

- Connect pins of the chips as follows. The chips all number their pins with 1
  at the top left of the notch and then down the left hand side, across the
  bottom and up the right hand side so that the maximum pin number is to the 
  /right/ of the notch.

- +5V refers to the positive on your 5V rail (connected to Pi's 5V output)

- +3.3V refers to the positive on your 3.3V rail (connected to the Pi's 3.3V
  output)

- GND refers to the associated ground rail next to the positive rail the same
  chip(s) is/are connected to.

	SN74LVC245A	SN74LS74	SN74LS31 	EPSON Clock chip
Bottom left						GND
7			GND
8					GND
10	GND
14			+5V
16					+5V
20	+3.3V
Top right						+5V (assuming 5V part!)

Connect pin 17 of the ADF10 (last in the longer line, nearest the edge of the
breadboard) to your +5V rail. Connect pin 16 of the ADF10 (next one down) to
GND.

Stage 7 - Install the bypass / decoupling capacitors
	  (I do not know which they are, but they are one or the other)
-----------------------------------------------------------------------

Install one capacitor on the same row of holes as GND on each of the chips 
above, connected to the next row down, away from the chip ("second side of
capacitor").

Next, connect a spare hole on the "second side of the capacitor" to a spare
hole in the row adjacent to the power pin on the chip (14, 16, or 20 depending
on the chip - see above).

Stage 8 - Wire up the data bus to the data bus level shifter and on to the Pi
-----------------------------------------------------------------------------

You should find that you have one of the two SN74LVC245 level shifters broadly
alongside the longer row of pins on the ADF10.

The ADF10 pins are numbered from 17 to 1 starting at the end nearest the edge
of the ADF10 board (which should mean pin 17 is nearest the edge of your 
breadboard and pin 1 furthest away).

Connect pins 14 to 7 (8 in total) on the ADF10 to pins 2-9 on the adjacent
level shifter. (If you look at a data sheet for the levelshifter, you'll find
those are named 'A1 to A8'.)

Next, we connect the 'B' side of the level shifter to the Pi. Whilst the wires
are all next to each other neatly in order on the level shifter, they are all
over the expansion module for the Pi's GPIOs. The reason is that the module
code reads/writes all 8 bits of the data bus simultaneously and does so
assuming that they are in sequential GPIOs. Whilst the GPIOs are /numbered/
seqentially inside the Pi, they /appear/ all over the place on the expansion
unit.

Connect as follows. I have found that tearing 8 wires off one of those 40-wire
strips where both ends have pins on them (male) and connecting them in order
at the level shifter end works well for this - it means the wiring looks neater.

Data bus level shifter pin number	Pi GPIO number (broadcom numbering)
18					27
17					26
16					25
15					24
14					23
13					22
12					21
11					20

Stage 9 - Connect the ADF10's /RST, A0, A1 and R/W pins to the GPIO
-------------------------------------------------------------------

These connections are all one way: from the Pi to the ADF10. The 3.3v outputs of the Pi are sufficient for the ADLC to register
a '1', so no level shifter is required. Connect as follows - again, pin numbers are described in stage 8 above.

ADF10 pin	Function	RPi GPIO number (Broadcom numbering - usually printed on the expander)
15		/RST		19
6		A1		13
5		A0		12
2		R /W		6

Stage 10 - Connect up the clock chip to the D-Type, and the delay line, and
then onto the ADF10
---------------------------------------------------------------------------

Connect the clock output of the clock chip (usually bottom right pin with notch
at top, variously pin 3, 5, or 8 even on 4-pin devices) to the 1CLK input of
the 74LS74 D-Type (pin 3).

Connect the same clock output direct from the clock chip to the 2A input of the
74LS31 delay line (pin 3).

Input 2A's output is 2Y (pin 4), and will introduce a 45ns-ish delay on the
clock. I have found we need a little more than that, so what we do it run it
through the delay again using 5A to 5Y. To achieve that:

- Connect pin 4 of the delayline (2Y output) to pin 13 (5A input* - which should
  be directly across the chip from the 2Y output).

- Then connect the delayed clock from the 5Y output (pin 12, one below the 5A
  input*) to the ADF10's clock input, pin 4.

* This does /not/ mean +5V input. It means the input labelled '5A' on the 
datasheet.

Stage 11 - Connect GPIO /CS output to the D-Type, and connect up the D-Type
output to the ADF10
---------------------------------------------------------------------------

The /CS output from the Pi is on GPIO 5. Connect that to the 1D input on the
D-Type Flip-Flop (74LS74), pin 2.

The Q output of the 74LS74 will now change to match the /CS output from the Pi
only on a clock low to high transition.

Connect the Q output of the 74LS74 (pin 5) to the /ADLC input (the circuit
diagram term for the 68B54's chip select line), which is pin 3 on the ADF10.

We also need to pull the 1/CLR and 1/PRE inputs on the D-Type to logic 1 (+5V)
to get it to do what we want, so:

- Connect pins 1 & 4 of the 74LS74 D-Type flipflop to the 5V power supply -
  either in the row of holes adjacent to pin 14 of that chip, or directly to
  the +5V power rail, it doesn't matter which.

Stage 12 - Connect the /CS Return feed, and the /IRQ output of the ADF10, to
the return level shifter
----------------------------------------------------------------------------

We also need a feed of the /CS signal as seen by the ADF10 fed back to the Pi
so that we can work out when the ADF10 is actually reading or writing to the
data bus. However, that signal will be a 5V signal as it comes out of the 5V
D-Type. We therefore have to run it through the second level shifter to get it
down to 3.3V for the Pi.

Here, references to 74LS74 are to the /secondary/ level shifter - the first one
is full of the data bus.

- Connect pin 5 of the 74LS74 to pin 8 ('A7' in the data sheet) on the second
  level shifter. This is in addition to pin 5 on the 74LS74 being connected to
  the ADF10 as above. 

- Connect pin 12 of the 74LS74 to the Pi's GPIO 18. 

Next we need to wire up the /IRQ output of the ADF10. This, too, is a 5V
signal, so it needs to go through the secondary level shifter.

Connect ADF10 pin 1 to pin 9 ('A8') on the 74LS74.

Connect pin 11 of the 74LS74 (bottom right, 'B8') to GPIO 17 on the Pi.

Stage 13 - Omitted for superstitious reasons
--------------------------------------------

Stage 14 - Ground the remaining inputs of the return level shifter
------------------------------------------------------------------

As we are not using 6 of the inputs on the return/secondary level shifter, they
need to be grounded becaues the data sheet says so.

Connect pins 2 to 7 on the secondary 74LS74 to 0V. I did this by connecting pin
2 to GND, and then using little tiny connector jumpers to go from 2 to 3, 3 to
4 and so on. Saves lots of wire hanging around the place.

It is not necessary to do this on the other side of this level shifter because
it will be fixed in one direction (A to B).

Stage 15 - Connect the DIR output of the Pi GPIO to the data bus level shifter
------------------------------------------------------------------------------

The data bus level shifter has to be told which direction to shift the data
in - we can read or write through it. The Pi has an output just for this
purpose.

Connect pin 1 of the data bus level shifter to Pi GPIO 16.

Stage 16 - Fix the direction of the return level shifter
--------------------------------------------------------

The secondary level shifter only ever goes in one direction - A to B. So we can
wire its pin 1 (DIR) input to 3.3V to achieve that.

Stage 17 - Fix the /OE (output enable) input on each level shifter to GND to
have output enabled all the time
----------------------------------------------------------------------------

Connect pin 19 (2nd down, right hand side) on each level shifter to GND.

Stage 18 - Connect ribbon cable to Pi
-------------------------------------

TAKE A BACKUP FIRST. THEN POWER OFF YOUR PI.
IF YOU HAVE DONE SOMETHING WRONG YOU MAY BLOW UP YOUR PI.
You have been warned.

Suggest double checking the above very carefully first.

Ensure Pi is powered off before connecting the ribbon cable from the expansion
adapter.

Then cross your fingers and turn the power on. The Pi should boot up as if 
nothing was any different from last time.

Stage 19 - Test
---------------

The Pi should boot normally. If not, power off - something is wrong. Check
wiring.

Install kernel module & compile utilities - see other readme.

Run test harness. Use your oscilloscope to check each signal is getting where
it is supposed to be.

The pins on the ADF10 17-pin side, running from top to bottom (if you look at
the board with the 68B54 in the top right (ish)) are:

17	+5V
16	GND
15	/RST			Chip reset (active low) from Pi
14-7	D7-D0 in that order	Data bus (7 high to 0 low)
6	A1			Register address line 1 (high bit)
5	A0			Register address line 0
4	CLOCK IN		The 1MHz clock (was 2MHz on a beeb, but 1 works
				fine) from the delay line *
3	/CS			Chip select - the ADLC only reads/writes the
				bus when selected * - active low
2	R /W			Controls whether we are writing or reading from
				the bus
1	/INT			Interrupt to Pi - active low

* /CS has to go active low not less than about 40ns before the clock goes high.
This is the purpose of the D-Type FlipFlop. The D-Type clocks the Pi's chip
select output through on a clock rise. That output (Q) is sent to the /CS input
of the ADF10. However, without the delay line, the /CS would go active low at
the *same time* as the clock went high, which is no good. So we put a delay of
90ns on the clock before it gets to the ADF10. A copy of the Q (/CS to ADF10)
output is then returned to the Pi so that the Pi can see when /CS goes active
low. It then waits just over half a clock duty cycle and puts its /CS output
inactive high again, which is then clocked through to the ADF10 on the next
clock high (as far as the D-Type sees it). Thus reliable reading and writing
of data off the data bus becomes possible.

Stage 20 - Try sniffing some network traffic
--------------------------------------------

Load the kernel module and run the econet-monitor utility. Press BREAK a few
times on a real Beeb on the Econet (so long as it has NFS / ANFS installed!)
and you should see (usually) 9 bridge solicitation packets, each having the
word 'BRIDGE' in their data portion.

Stage 21 - Try sending some immediate traffic to a working station
------------------------------------------------------------------

Next, try using the econet-imm utility to do a machine or memory query, or
halt/continue a real BBC. For the latter three queries, you will need to ensure
that the BBC is not in *PROT (protected) mode for the operation in question.

Stage 22 - Try the bridge
-------------------------

See other documentation

Stage 23 - Enjoy
----------------

Enjoy!


CR, June 2021


