/* Convert unix 0x0A terminated lines to 0x0D for beeb
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main (int argc, char **argv)
{

	int	opt;
	FILE 	*in, *out;
	unsigned char	infile[1024], outfile[1024];
	uint8_t	tr_mode = 0; // Beeb to Unix
	int	c;

	infile[0] = outfile[0] = 0;

	while ((opt = getopt(argc, argv, "i:o:rh")) != -1)
	{
		switch (opt)
		{
			case 'h':
				fprintf (stderr, "%s: Convert unix to beeb text format files and vice versa\n\n\
-i <file>	: Input file (mandatory)\n\
-o <file>	: Output file (mandatory)\n\
-r		: Convert beeb to unix rather than beeb to unix\n\
-h		: This help\n\
\n\n", argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'i':
				strncpy(infile, optarg, 1023);
				break;
			case 'o':
				strncpy(outfile, optarg, 1023);
				break;
			case 'r':
				tr_mode = 1; 
				break;
		}
	}

	if (infile[0] == 0)
	{
		fprintf (stderr, "No input file specified with -i switch.\n");
		exit (EXIT_FAILURE);
	}

	if (outfile[0] == 0)
	{
		fprintf (stderr, "No output file specified with -o switch.\n");
		exit (EXIT_FAILURE);
	}

	if (!(in = fopen(infile, "r")))
	{
		fprintf (stderr, "Cannot open input file %s (%s)\n", infile, strerror(errno));
		exit (EXIT_FAILURE);
	}

	if (!(out = fopen(outfile, "w")))
	{
		fprintf (stderr, "Cannot open output file %s (%s)\n", outfile, strerror(errno));
		exit (EXIT_FAILURE);
	}

	while ((c = fgetc(in)) != EOF)
	{
		if (c == (tr_mode ? 0x0d : 0x0a))
			c = (tr_mode ? 0x0a : 0x0d);
		fputc(c, out);
	}

	fclose (in); fclose (out);
}
