#include <stdio.h>

#include "veritas.h"
#include "elf.h"

int main(int argc, char *argv[])
{
	FILE *f;
	int err;

	if (argc != 2)
	{
		printf("Syntax: veritas <microcode.uc>\n");
		return -1;
	}

	f = fopen(argv[1], "rb");
	if (!f)
	{
		printf("Unable to open %s\n", argv[1]);
		return -1;
	}

	printf("File \"%s\".\n\n", argv[1]);

	err = elf_process(f);
	if (err)
		return err;

	fclose(f);

	return 0;
}