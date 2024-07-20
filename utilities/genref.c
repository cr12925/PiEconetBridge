#include <stdio.h>


void main(void)
{

	FILE *out;

	out = fopen("/econet/0ECONET/SYSTEM/REFERENCE", "w");

	if (out)
	{
		unsigned int count = 1;

		while (ftell(out) < 4096)
		{
			fprintf (out, "%d\n", count++);
		}

		fclose(out);

	}
}

