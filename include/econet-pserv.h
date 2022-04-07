/*
  (c) 2021 Chris Royle
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

#ifndef __ECONETPSERV_H__
#define __ECONETPSERV_H__

#define MAILCMDSPEC "/usr/sbin/sendmail %s < %s"
#define PRINTCMDSPEC "/usr/bin/lp -s -o sides=two-sided-long-edge -d %s %s"
#define SPOOLFILESPEC "/tmp/econet-gpio-printjob-%d-%d"
#define PRINTHEADER "*** Pi Econet AUN Bridge Print Server***\n\r*** Print job from station %d.%d ***\n\n\r"
#define PRINTFOOTER "\014" // Form feed

#endif
