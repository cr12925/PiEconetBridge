/*
  (c) 2024 Chris Royle
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

#include "fs.h"

/*
 * Implements *INFO <fsp>
 */

FSOP_00(INFO)
{
	FS_R_DATA(0x80);

        struct path pt;

        unsigned char path[1024];
        unsigned char relative_to;
        char reply_string[ECONET_ABS_MAX_FILENAME_LENGTH+80];

        relative_to = FSOP_CWD;

	FSOP_EXTRACT(f,0,path,255);

        r.p.data[0] = 0x04; // Anything else and we get weird results. 0x05, for example, causes the client machine to *RUN the file immediately after getting the answer...
        r.p.data[1] = 0;

        fs_debug (0, 2, "%12sfrom %3d.%3d *INFO %s", "", f->net, f->stn, path);

        if (!fsop_normalize_path_wildcard(f, path, relative_to, &pt, 1))
                fsop_error(f, 0xD6, "Not found");
        else
        {
		uint8_t		is_owner;
		uint8_t		mdfsinfo;

		is_owner = FS_PERM_EFFOWNER(f->active, pt.owner);
		mdfsinfo = FS_CONFIG(f->server,fs_mdfsinfo);

                // 20240107 Added - we only want the first one
                fs_free_wildcard_list(&pt);

                if (pt.ftype == FS_FTYPE_NOTFOUND)
                        fsop_error(f, 0xD6, "Not found");
                else if (pt.ftype != FS_FTYPE_FILE)
                        fsop_error(f, 0xD6, "Not a file");
                else if (!is_owner && (pt.perm & FS_PERM_H)) // Hidden file
                        fsop_error(f, 0xD6, "Not found");
                else
                {
                        unsigned char permstring[10];
                        unsigned char hr_fmt_string[100];

                        strcpy(permstring, "");

                        if (FS_CONFIG(f->server,fs_mask_dir_wrr) && pt.ftype == FS_FTYPE_DIR && (pt.perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
                                pt.perm &= ~(FS_ACORN_DIR_MASK);

                        if (pt.perm & FS_PERM_L) strcat (permstring, "L"); else strcat (permstring, " ");
			if (pt.perm & FS_PERM_EXEC) strcat (permstring, "E"); else strcat (permstring, " ");
                        if (pt.perm & FS_PERM_OWN_W) strcat (permstring, (is_owner ? "W" : mdfsinfo ? "w" : "W")); else strcat (permstring, " ");
                        if (pt.perm & FS_PERM_OWN_R) strcat (permstring, (is_owner ? "R" : mdfsinfo ? "r" : "R")); else strcat (permstring, " ");
                        strcat (permstring, "/");
                        if (pt.perm & FS_PERM_OTH_W) strcat (permstring, (mdfsinfo ? (is_owner ? "w" : "W") : "W"));
                        if (pt.perm & FS_PERM_OTH_R) strcat (permstring, (mdfsinfo ? (is_owner ? "r" : "R") : "R"));

                        if (mdfsinfo)
                        {
                                // Longer output
                                sprintf(hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX   %%-7s    %%02d/%%02d/%%02d %%02d/%%02d/%%02d %%02d:%%02d:%%02d%%c%%c", ECONET_MAX_FILENAME_LENGTH);
                                sprintf(reply_string, hr_fmt_string, pt.acornname, pt.load, pt.exec, pt.length, permstring,
                                                fs_day_from_two_bytes(pt.c_day, pt.c_monthyear),
                                                fs_month_from_two_bytes(pt.c_day, pt.c_monthyear),
                                                fs_year_from_two_bytes(pt.c_day, pt.c_monthyear),
                                                fs_day_from_two_bytes(pt.day, pt.monthyear),
                                                fs_month_from_two_bytes(pt.day, pt.monthyear),
                                                fs_year_from_two_bytes(pt.day, pt.monthyear),
                                                pt.hour, pt.min, pt.sec,
                                                0x0d, 0x80);
                        }
                        else
                        {
                                sprintf(hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX   %%-7s    %%02d/%%02d/%%02d %%06lX%%c%%c", ECONET_MAX_FILENAME_LENGTH);
                                sprintf(reply_string, hr_fmt_string, pt.acornname, pt.load, pt.exec, pt.length, permstring,
                                                fs_day_from_two_bytes(pt.day, pt.monthyear),
                                                fs_month_from_two_bytes(pt.day, pt.monthyear),
                                                fs_year_from_two_bytes(pt.day, pt.monthyear),
                                                pt.internal, 0x0d, 0x80);
                        }

                        strcpy(&(r.p.data[2]), reply_string);

                        fsop_aun_send(&r, strlen(reply_string)+2, f);
                }
	}
}

