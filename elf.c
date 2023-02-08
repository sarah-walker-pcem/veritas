#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "veritas.h"
#include "elf.h"
#include "verite_disasm.h"

//#define ELF_DEBUG

#define ET_EXEC 2
#define ELF_MACHINE_VERITE 0x3d32

typedef struct elf_header_t
{
	struct {
		uint8_t magic[4];
		uint8_t class;
		uint8_t data;
		uint8_t version;
		uint8_t abi;
		uint8_t abi_version;
		uint8_t padding[7];
	} ident;

	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint32_t entry;
	uint32_t phoff;
	uint32_t shoff;
	uint32_t flags;

	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;
} elf_header_t;

typedef struct elf_program_header_t
{
	uint32_t type;
	uint32_t offset;
	uint32_t vaddr;
	uint32_t paddr;
	uint32_t filesz;
	uint32_t memsz;
	uint32_t flags;
	uint32_t align;
} elf_program_header_t;

typedef struct elf_section_header_t
{
	uint32_t name;
	uint32_t type;
	uint32_t flags;
	uint32_t addr;
	uint32_t offset;
	uint32_t size;
	uint32_t link;
	uint32_t info;
	uint32_t addralign;
	uint32_t entsize;
} elf_section_header_t;

typedef struct elf_t
{
	elf_header_t header;
	elf_program_header_t *program_headers;
	elf_section_header_t *section_headers;
	
	char *string_table;
	unsigned int string_table_len;
} elf_t;


static uint16_t read_bend_16(FILE *f)
{
	uint8_t v[2];

	v[0] = getc(f);
	v[1] = getc(f);

	return v[1] | (v[0] << 8);
}

static uint32_t read_bend_32(FILE *f)
{
	uint8_t v[4];

	v[0] = getc(f);
	v[1] = getc(f);
	v[2] = getc(f);
	v[3] = getc(f);

	return v[3] | (v[2] << 8) | (v[1] << 16) | (v[0] << 24);
}

static int elf_process_header(FILE *f, elf_t *elf)
{
	elf_header_t *header = &elf->header;

	fread(&header->ident, 16, 1, f);

	header->type = read_bend_16(f);
	header->machine = read_bend_16(f);

	header->version = read_bend_32(f);
	header->entry = read_bend_32(f);
	header->phoff = read_bend_32(f);
	header->shoff = read_bend_32(f);
	header->flags = read_bend_32(f);

	header->ehsize = read_bend_16(f);
	header->phentsize = read_bend_16(f);
	header->phnum = read_bend_16(f);
	header->shentsize = read_bend_16(f);
	header->shnum = read_bend_16(f);
	header->shstrndx = read_bend_16(f);

	/*Verify header*/
	if (header->ident.magic[0] != 0x7f || header->ident.magic[1] != 'E' ||
	    header->ident.magic[2] != 'L' || header->ident.magic[3] != 'F')
	{
		printf("Not an ELF image.\n");
		return -1;
	}
	if (header->ident.class != 1)
	{
		printf("ELF image not 32-bit.\n");
		return -1;
	}
	if (header->ident.data != 2)
	{
		printf("ELF image not big endian.\n");
		return -1;
	}
	if (header->ident.version != 1)
	{
		printf("Unknown ELF header version.\n");
		return -1;
	}
	if (header->type != ET_EXEC)
	{
		printf("Not an executable ELF image.\n");
		return -1;
	}
	if (header->machine != ELF_MACHINE_VERITE)
	{
		printf("Not a Verite image.\n");
		return -1;
	}
	if (header->shstrndx >= header->shnum)
	{
		printf("ELF strings section out of range.\n");
		return -1;
	}

#ifdef ELF_DEBUG
	printf("ELF header:\n");
	printf("  Type=%04x\n", header->type);
	printf("  Machine=%04x\n", header->machine);

	printf("  Entry point=%08x\n", header->entry);
	printf("  Program header offset=%08x\n", header->phoff);
	printf("  Section header offset=%08x\n", header->shoff);
	printf("  Flags=%08x\n", header->flags);
	printf("  Program header entry size=%08x\n", header->phentsize);
	printf("  Program header entry num=%08x\n", header->phnum);
	printf("  Section header entry size=%08x\n", header->shentsize);
	printf("  Section header entry num=%08x\n", header->shnum);
	printf("  Section name index=%x\n", header->shstrndx);
#endif

	return 0;
}

static int elf_process_section_headers(FILE *f, elf_t *elf)
{
	elf_header_t *header = &elf->header;
	elf_section_header_t *section_headers = malloc(header->shnum * sizeof(*section_headers));

	elf->section_headers = section_headers;

	fseek(f, header->shoff, SEEK_SET);

	for (int i = 0; i < header->shnum; i++)
	{
		section_headers[i].name = read_bend_32(f);
		section_headers[i].type = read_bend_32(f);
		section_headers[i].flags = read_bend_32(f);
		section_headers[i].addr = read_bend_32(f);
		section_headers[i].offset = read_bend_32(f);
		section_headers[i].size = read_bend_32(f);
		section_headers[i].link = read_bend_32(f);
		section_headers[i].info = read_bend_32(f);
		section_headers[i].addralign = read_bend_32(f);
		section_headers[i].entsize = read_bend_32(f);
	}

	/*Read in string table.*/
	fseek(f, section_headers[header->shstrndx].offset, SEEK_SET);
	elf->string_table_len = section_headers[header->shstrndx].size;
	elf->string_table = malloc(elf->string_table_len + 1);
	fread(elf->string_table, elf->string_table_len, 1, f);
	elf->string_table[elf->string_table_len] = 0;


#ifdef ELF_DEBUG
	printf("\nSection headers:\n");

	for (int i = 0; i < header->shnum; i++)
	{
		printf("  Header %i:\n", i);
		printf("    Name=%08x (%s)\n", section_headers[i].name, &elf->string_table[section_headers[i].name]);
		printf("    Type=%08x\n", section_headers[i].type);
		printf("    Flags=%08x\n", section_headers[i].flags);
		printf("    Addr=%08x\n", section_headers[i].addr);
		printf("    Offset=%08x\n", section_headers[i].offset);
		printf("    Size=%08x\n", section_headers[i].size);
		printf("    Link=%08x\n", section_headers[i].link);
		printf("    Info=%08x\n", section_headers[i].info);
		printf("    Address alignment=%08x\n", section_headers[i].addralign);
		printf("    Entry size=%08x\n", section_headers[i].entsize);
	}
#endif

	return 0;
}

static int elf_process_program_headers(FILE *f, elf_t *elf)
{
	elf_header_t *header = &elf->header;
	elf_program_header_t *program_headers = malloc(header->phnum * sizeof(*program_headers));

	elf->program_headers = program_headers;

	fseek(f, header->phoff, SEEK_SET);

#ifdef ELF_DEBUG
	printf("\nProgram headers:\n");
#endif

	for (int i = 0; i < header->phnum; i++)
	{
		program_headers[i].type = read_bend_32(f);
		program_headers[i].offset = read_bend_32(f);
		program_headers[i].vaddr = read_bend_32(f);
		program_headers[i].paddr = read_bend_32(f);
		program_headers[i].filesz = read_bend_32(f);
		program_headers[i].memsz = read_bend_32(f);
		program_headers[i].flags = read_bend_32(f);
		program_headers[i].align = read_bend_32(f);

#ifdef ELF_DEBUG
		printf("  Header %i:\n", i);
		printf("    Type=%08x\n", program_headers[i].type);
		printf("    Offset=%08x\n", program_headers[i].offset);
		printf("    Virtual address=%08x\n", program_headers[i].vaddr);
		printf("    Physical address=%08x\n", program_headers[i].paddr);
		printf("    File size=%08x\n", program_headers[i].filesz);
		printf("    Mem size=%08x\n", program_headers[i].memsz);
		printf("    Flags=%08x\n", program_headers[i].flags);
#endif
	}

	return 0;
}

static int elf_process_text_section(FILE *f, elf_t *elf)
{
	elf_section_header_t *section_headers = elf->section_headers;
	elf_section_header_t *text = NULL;
	void *data;

	for (int i = 0; i < elf->header.shnum; i++)
	{
		if (section_headers[i].name >= elf->string_table_len)
		{
			printf("ELF Section %i name out of range of string table.\n");
			continue;
		}
		char *name = &elf->string_table[section_headers[i].name];

		if (!strcmp(name, ".text"))
		{
			text = &section_headers[i];
			break;
		}
	}

	if (!text)
	{
		printf("Can't find ELF text section.\n");
		return -1;
	}

	printf("Start address 0x%x.\n\n", text->addr);
	printf("Disassembly of section .text:\n\n");

#ifdef ELF_DEBUG
	printf("  offset=%08x\n", text->offset);
	printf("  addr=%08x\n", text->addr);
	printf("  size=%08x\n", text->size);
#endif

	data = malloc(text->size);
	fseek(f, text->offset, SEEK_SET);
	fread(data, text->size, 1, f);

	verite_disassemble(data, text->addr, text->size);

	free(data);
}

int elf_process(FILE *f)
{
	elf_t elf;
	int err;

	err = elf_process_header(f, &elf);
	if (err)
		goto err_out;
	
	err = elf_process_section_headers(f, &elf);
	if (err)
		goto err_out;

	err = elf_process_program_headers(f, &elf);
	if (err)
		goto err_free_section_headers;

	err = elf_process_text_section(f, &elf);
	if (err)
		goto err_free_program_headers;

err_free_program_headers:
	free(elf.program_headers);

err_free_section_headers:
	free(elf.section_headers);
	free(elf.string_table);

err_out:
	return err;
}