#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "veritas.h"
#include "verite_disasm.h"

static uint32_t be_to_le(uint32_t be_data)
{
	return (be_data >> 24) | ((be_data >> 8) & 0xff00) | ((be_data << 8) & 0xff0000) | (be_data << 24);
}

#define OPCODE_IMM_MASK 0xffff
#define OPCODE_D_SHIFT 16
#define OPCODE_D_MASK (0xff << OPCODE_D_SHIFT)
#define OPCODE_S2_SHIFT 8
#define OPCODE_S2_MASK (0xff << OPCODE_S2_SHIFT)
#define OPCODE_S1_SHIFT 0
#define OPCODE_S1_MASK (0xff << OPCODE_S1_SHIFT)
#define OPCODE_INT_IMM_MASK OPCODE_S1_MASK

#define OPCODE_STORE_OFFSET_SHIFT 16
#define OPCODE_STORE_OFFSET_MASK (0xff << OPCODE_STORE_OFFSET_SHIFT)
#define OPCODE_LOAD_OFFSET_SHIFT 8
#define OPCODE_LOAD_OFFSET_MASK (0xff << OPCODE_LOAD_OFFSET_SHIFT)

#define OPCODE_BRANCH_OFFSET_SHIFT 8
#define OPCODE_BRANCH_OFFSET_MASK (0xffff << OPCODE_BRANCH_OFFSET_SHIFT)

#define OPCODE_SPRII_OFFSET_SHIFT 8
#define OPCODE_SPRII_OFFSET_MASK (0xffff << OPCODE_BRANCH_OFFSET_SHIFT)

enum op_types
{
	OP_TYPE_INTEGER,
	OP_TYPE_INTEGER_IMM,
	OP_TYPE_LOAD,
	OP_TYPE_STORE,
	OP_TYPE_SORT,
	OP_TYPE_LOAD_IMM,
	OP_TYPE_SPRII,
	OP_TYPE_BRANCH,
	OP_TYPE_JUMP_ABS,
	OP_TYPE_JUMP_REL,
	OP_TYPE_OTHER
} op_types;

static struct
{
	const char *name;
	enum op_types op_type;
	int offset_mul;
} opcodes[256] =
{
	[0x00] = { .name = "add", .op_type = OP_TYPE_INTEGER_IMM },
	[0x01] = { .name = "sub", .op_type = OP_TYPE_INTEGER_IMM },
	[0x02] = { .name = "andn", .op_type = OP_TYPE_INTEGER_IMM },
	[0x03] = { .name = "subf", .op_type = OP_TYPE_INTEGER_IMM },
	[0x04] = { .name = "and", .op_type = OP_TYPE_INTEGER_IMM },
	[0x05] = { .name = "or", .op_type = OP_TYPE_INTEGER_IMM },
	[0x06] = { .name = "nor", .op_type = OP_TYPE_INTEGER_IMM },
	[0x07] = { .name = "xor", .op_type = OP_TYPE_INTEGER_IMM },
	[0x08] = { .name = "mul", .op_type = OP_TYPE_INTEGER_IMM },
	[0x09] = { .name = "mulsr8", .op_type = OP_TYPE_INTEGER_IMM },
	[0x0a] = { .name = "mulsr16", .op_type = OP_TYPE_INTEGER_IMM },
	[0x0b] = { .name = "mulsr24", .op_type = OP_TYPE_INTEGER_IMM },
	[0x0c] = { .name = "mulsr32", .op_type = OP_TYPE_INTEGER_IMM },
	[0x0d] = { .name = "mulsr31", .op_type = OP_TYPE_INTEGER_IMM },
	[0x0e] = { .name = "clip", .op_type = OP_TYPE_OTHER },
	[0x0f] = { .name = "f2i", .op_type = OP_TYPE_INTEGER_IMM },

	[0x10] = { .name = "add", .op_type = OP_TYPE_INTEGER },
	[0x11] = { .name = "sub", .op_type = OP_TYPE_INTEGER },
	[0x12] = { .name = "andn", .op_type = OP_TYPE_INTEGER },
	[0x13] = { .name = "subf", .op_type = OP_TYPE_INTEGER },
	[0x14] = { .name = "and", .op_type = OP_TYPE_INTEGER },
	[0x15] = { .name = "or", .op_type = OP_TYPE_INTEGER },
	[0x16] = { .name = "nor", .op_type = OP_TYPE_INTEGER },
	[0x17] = { .name = "xor", .op_type = OP_TYPE_INTEGER },
	[0x18] = { .name = "mul", .op_type = OP_TYPE_INTEGER },
	[0x19] = { .name = "mulsr8", .op_type = OP_TYPE_INTEGER },
	[0x1a] = { .name = "mulsr16", .op_type = OP_TYPE_INTEGER },
	[0x1b] = { .name = "mulsr24", .op_type = OP_TYPE_INTEGER },
	[0x1c] = { .name = "mulsr32", .op_type = OP_TYPE_INTEGER },
	[0x1d] = { .name = "mulsr31", .op_type = OP_TYPE_INTEGER },
	[0x1e] = { .name = "clip", .op_type = OP_TYPE_OTHER },
	[0x1f] = { .name = "f2i", .op_type = OP_TYPE_INTEGER },

	[0x20] = { .name = "add.v", .op_type = OP_TYPE_INTEGER },
	[0x21] = { .name = "sub.v", .op_type = OP_TYPE_INTEGER },
	[0x22] = { .name = "andn.v", .op_type = OP_TYPE_INTEGER },
	[0x23] = { .name = "subf.v", .op_type = OP_TYPE_INTEGER },
	[0x24] = { .name = "and.v", .op_type = OP_TYPE_INTEGER },
	[0x25] = { .name = "or.v", .op_type = OP_TYPE_INTEGER },
	[0x26] = { .name = "nor.v", .op_type = OP_TYPE_INTEGER },
	[0x27] = { .name = "xor.v", .op_type = OP_TYPE_INTEGER },
	[0x28] = { .name = "mul.v", .op_type = OP_TYPE_INTEGER },
	[0x29] = { .name = "mulsr8.v", .op_type = OP_TYPE_INTEGER },
	[0x2a] = { .name = "mulsr16.v", .op_type = OP_TYPE_INTEGER },
	[0x2b] = { .name = "mulsr24.v", .op_type = OP_TYPE_INTEGER },
	[0x2c] = { .name = "mulsr32.v", .op_type = OP_TYPE_INTEGER },
	[0x2d] = { .name = "mulsr31.v", .op_type = OP_TYPE_INTEGER },
	[0x2e] = { .name = "clip.v", .op_type = OP_TYPE_OTHER },

	[0x30] = { .name = "add.vs", .op_type = OP_TYPE_INTEGER },
	[0x31] = { .name = "sub.vs", .op_type = OP_TYPE_INTEGER },
	[0x32] = { .name = "andn.vs", .op_type = OP_TYPE_INTEGER },
	[0x33] = { .name = "subf.vs", .op_type = OP_TYPE_INTEGER },
	[0x34] = { .name = "and.vs", .op_type = OP_TYPE_INTEGER },
	[0x35] = { .name = "or.vs", .op_type = OP_TYPE_INTEGER },
	[0x36] = { .name = "nor.vs", .op_type = OP_TYPE_INTEGER },
	[0x37] = { .name = "xor.vs", .op_type = OP_TYPE_INTEGER },
	[0x38] = { .name = "mul.vs", .op_type = OP_TYPE_INTEGER },
	[0x39] = { .name = "mulsr8.vs", .op_type = OP_TYPE_INTEGER },
	[0x3a] = { .name = "mulsr16.vs", .op_type = OP_TYPE_INTEGER },
	[0x3b] = { .name = "mulsr24.vs", .op_type = OP_TYPE_INTEGER },
	[0x3c] = { .name = "mulsr32.vs", .op_type = OP_TYPE_INTEGER },
	[0x3d] = { .name = "mulsr31.vs", .op_type = OP_TYPE_INTEGER },
	[0x3e] = { .name = "clip.vs", .op_type = OP_TYPE_OTHER },

	[0x40] = { .name = "addif", .op_type = OP_TYPE_OTHER },
	[0x41] = { .name = "subif", .op_type = OP_TYPE_OTHER },
	[0x42] = { .name = "seedsr", .op_type = OP_TYPE_INTEGER_IMM },
	[0x43] = { .name = "subfif", .op_type = OP_TYPE_INTEGER_IMM },
	[0x44] = { .name = "rotr", .op_type = OP_TYPE_INTEGER_IMM },
	[0x45] = { .name = "sl", .op_type = OP_TYPE_INTEGER_IMM },
	[0x46] = { .name = "asr", .op_type = OP_TYPE_INTEGER_IMM },
	[0x47] = { .name = "sr", .op_type = OP_TYPE_INTEGER_IMM },
	[0x48] = { .name = "slt", .op_type = OP_TYPE_INTEGER_IMM },
	[0x49] = { .name = "sltu", .op_type = OP_TYPE_INTEGER_IMM },
	[0x4a] = { .name = "seq", .op_type = OP_TYPE_INTEGER_IMM },
	[0x4b] = { .name = "addsl8", .op_type = OP_TYPE_INTEGER_IMM },
	[0x4c] = { .name = "min", .op_type = OP_TYPE_INTEGER_IMM },
	[0x4d] = { .name = "max", .op_type = OP_TYPE_INTEGER_IMM },
	[0x4e] = { .name = "sprii", .op_type = OP_TYPE_SPRII },
	[0x4f] = { .name = "spri", .op_type = OP_TYPE_OTHER },

	[0x52] = { .name = "abs", .op_type = OP_TYPE_OTHER },
	[0x53] = { .name = "seedsr", .op_type = OP_TYPE_INTEGER },
	[0x54] = { .name = "rotr", .op_type = OP_TYPE_INTEGER },
	[0x55] = { .name = "sl", .op_type = OP_TYPE_INTEGER },
	[0x56] = { .name = "asr", .op_type = OP_TYPE_INTEGER },
	[0x57] = { .name = "sr", .op_type = OP_TYPE_INTEGER },
	[0x58] = { .name = "slt", .op_type = OP_TYPE_INTEGER },
	[0x59] = { .name = "sltu", .op_type = OP_TYPE_INTEGER },
	[0x5a] = { .name = "seq", .op_type = OP_TYPE_INTEGER },
	[0x5c] = { .name = "min", .op_type = OP_TYPE_INTEGER },
	[0x5d] = { .name = "max", .op_type = OP_TYPE_INTEGER },
	[0x5e] = { .name = "at", .op_type = OP_TYPE_INTEGER },
	[0x5f] = { .name = "spr", .op_type = OP_TYPE_OTHER },

	[0x60] = { .name = "bez", .op_type = OP_TYPE_BRANCH },
	[0x61] = { .name = "bnez", .op_type = OP_TYPE_BRANCH },
	[0x62] = { .name = "bgez", .op_type = OP_TYPE_BRANCH },
	[0x63] = { .name = "blz", .op_type = OP_TYPE_BRANCH },
	[0x64] = { .name = "bgz", .op_type = OP_TYPE_BRANCH },
	[0x65] = { .name = "blez", .op_type = OP_TYPE_BRANCH },
	[0x68] = { .name = "rjmp", .op_type = OP_TYPE_OTHER },
	[0x6a] = { .name = "rjmpl", .op_type = OP_TYPE_OTHER },
	[0x6b] = { .name = "getpc", .op_type = OP_TYPE_OTHER },
	[0x6c] = { .name = "jmp", .op_type = OP_TYPE_OTHER },
	[0x6d] = { .name = "halt", .op_type = OP_TYPE_OTHER },
	[0x6e] = { .name = "jmpl", .op_type = OP_TYPE_OTHER },
	[0x6f] = { .name = "jmprl", .op_type = OP_TYPE_OTHER },

	[0x70] = { .name = "lb", .op_type = OP_TYPE_LOAD, .offset_mul = 1 },
	[0x71] = { .name = "lh", .op_type = OP_TYPE_LOAD, .offset_mul = 2 },
	[0x72] = { .name = "lw", .op_type = OP_TYPE_LOAD, .offset_mul = 4 },
	[0x73] = { .name = "pre", .op_type = OP_TYPE_OTHER, .offset_mul = 8 },
	[0x74] = { .name = "lv", .op_type = OP_TYPE_LOAD, .offset_mul = 8 },
	[0x75] = { .name = "lvra", .op_type = OP_TYPE_LOAD, .offset_mul = 8 },
	[0x76] = { .name = "li", .op_type = OP_TYPE_LOAD_IMM },
	[0x77] = { .name = "lui", .op_type = OP_TYPE_LOAD_IMM },
	[0x78] = { .name = "sb", .op_type = OP_TYPE_STORE, .offset_mul = 1 },
	[0x79] = { .name = "sh", .op_type = OP_TYPE_STORE, .offset_mul = 2 },
	[0x7a] = { .name = "sw", .op_type = OP_TYPE_STORE, .offset_mul = 4 },
	[0x7c] = { .name = "sv", .op_type = OP_TYPE_STORE, .offset_mul = 8 },
	[0x7d] = { .name = "sy", .op_type = OP_TYPE_STORE, .offset_mul = 8 },
	[0x7e] = { .name = "scr", .op_type = OP_TYPE_STORE, .offset_mul = 8 },
	[0x7f] = { .name = "scb", .op_type = OP_TYPE_STORE, .offset_mul = 8 },

	[0xc0] = { .name = "getxy", .op_type = OP_TYPE_OTHER },
	[0xc1] = { .name = "getyx", .op_type = OP_TYPE_OTHER },
	[0xc2] = { .name = "getra", .op_type = OP_TYPE_OTHER },
	[0xc3] = { .name = "getgb", .op_type = OP_TYPE_OTHER },
	[0xc4] = { .name = "sort", .op_type = OP_TYPE_INTEGER },

	[0xd0] = { .name = "step x/y", .op_type = OP_TYPE_OTHER },
	[0xd1] = { .name = "step q", .op_type = OP_TYPE_OTHER },
	[0xd2] = { .name = "step r/b", .op_type = OP_TYPE_OTHER },
	[0xd3] = { .name = "step i/v", .op_type = OP_TYPE_OTHER },
	[0xd4] = { .name = "step f", .op_type = OP_TYPE_OTHER },
	[0xd5] = { .name = "step g/b", .op_type = OP_TYPE_OTHER },
	[0xd6] = { .name = "step z/a", .op_type = OP_TYPE_OTHER },
	[0xd7] = { .name = "step cnt", .op_type = OP_TYPE_OTHER },
	[0xd8] = { .name = "step xy", .op_type = OP_TYPE_OTHER },
	[0xd9] = { .name = "step qu", .op_type = OP_TYPE_OTHER },
	[0xda] = { .name = "step rv", .op_type = OP_TYPE_OTHER },
	[0xdb] = { .name = "step iv", .op_type = OP_TYPE_OTHER },
	[0xdc] = { .name = "step zv", .op_type = OP_TYPE_OTHER },
	[0xdd] = { .name = "step gb", .op_type = OP_TYPE_OTHER },
	[0xde] = { .name = "step za", .op_type = OP_TYPE_OTHER },
	[0xdf] = { .name = "step cnt", .op_type = OP_TYPE_OTHER },

	[0xe0] = { .name = "drawp", .op_type = OP_TYPE_INTEGER },
	[0xe1] = { .name = "rdrawp", .op_type = OP_TYPE_INTEGER },
	[0xe4] = { .name = "drawpxy", .op_type = OP_TYPE_INTEGER },
	[0xe5] = { .name = "rdrawpxy", .op_type = OP_TYPE_INTEGER },

	[0xe7] = { .name = "mbltfo", .op_type = OP_TYPE_INTEGER },
	[0xe8] = { .name = "fill", .op_type = OP_TYPE_INTEGER },
	[0xe9] = { .name = "mbrush", .op_type = OP_TYPE_INTEGER },
	[0xea] = { .name = "mblt", .op_type = OP_TYPE_INTEGER },
	[0xeb] = { .name = "mbltf", .op_type = OP_TYPE_INTEGER },
	[0xec] = { .name = "cbrush8", .op_type = OP_TYPE_INTEGER },
	[0xed] = { .name = "cbrush16", .op_type = OP_TYPE_INTEGER },
	[0xee] = { .name = "cbrush32", .op_type = OP_TYPE_INTEGER },
	[0xef] = { .name = "cbltf", .op_type = OP_TYPE_INTEGER },

	[0xf0] = { .name = "draw1", .op_type = OP_TYPE_INTEGER },
	[0xf1] = { .name = "rdraw1", .op_type = OP_TYPE_INTEGER },
	[0xf2] = { .name = "draw2", .op_type = OP_TYPE_INTEGER },
	[0xf3] = { .name = "rdraw2", .op_type = OP_TYPE_INTEGER },
	[0xf8] = { .name = "draw3", .op_type = OP_TYPE_INTEGER },
	[0xf9] = { .name = "rdraw3", .op_type = OP_TYPE_INTEGER },
	[0xfa] = { .name = "draw4", .op_type = OP_TYPE_INTEGER },
	[0xfb] = { .name = "rdraw4", .op_type = OP_TYPE_INTEGER },
	[0xfc] = { .name = "draw5", .op_type = OP_TYPE_INTEGER },
	[0xfd] = { .name = "rdraw5", .op_type = OP_TYPE_INTEGER },
	[0xfe] = { .name = "tri", .op_type = OP_TYPE_INTEGER },
};

static const char *register_names[256] =
{
	[255] = "fp",
	[254] = "ra",
	[253] = "ira",
	[252] = "sp",

	[57] = "msk11",
	[56] = "msk12",

	[47] = "riscintr",
	[46] = "winclip",

	[41] = "npfifo",
	[40] = "npswfifo",
	[39] = "timer",
	[38] = "clip",
	[37] = "flag",
	[36] = "scale",
	[35] = "seg",
	[34] = "seed",
	[33] = "fifo",
	[32] = "swfifo",
	[31] = "f800",
	[30] = "f000",
	[29] = "e800",
	[28] = "e000",
	[27] = "d800",
	[26] = "d000",
	[25] = "c800",
	[24] = "c000",
	[23] = "b800",
	[22] = "b000",
	[21] = "bit17",
	[20] = "bit23",
	[19] = "bit25",
	[18] = "fpfrac",
	[17] = "bit16",
	[16] = "allfs",
	[15] = "if1_0",
	[14] = "zer3",
	[13] = "minus1",
	[12] = "zer2",
	[11] = "b1b3msk",
	[10] = "b0b2msk",
	[9] = "h1msk",
	[8] = "h0msk",
	[7] = "b3msk",
	[6] = "b2msk",
	[5] = "b1msk",
	[4] = "b0msk",
	[3] = "msb",
	[2] = "if0_5",
	[1] = "zer1",
	[0] = "zero"
};

static void get_register_name(char *dest, uint8_t reg)
{
	if (register_names[reg])
		strcpy(dest, register_names[reg]);
	else
		sprintf(dest, "%%%i", reg);
}

static void get_dest_register_name(char *dest, uint32_t opcode)
{
	int reg = (opcode & OPCODE_D_MASK) >> OPCODE_D_SHIFT;
	if (reg == 40)
	{
		/*40 is different registers for read/write*/
		strcpy(dest, "drawctl");
	}
	else
		get_register_name(dest, (opcode & OPCODE_D_MASK) >> OPCODE_D_SHIFT);
}
static void get_s2_register_name(char *dest, uint32_t opcode)
{
	get_register_name(dest, (opcode & OPCODE_S2_MASK) >> OPCODE_S2_SHIFT);
}
static void get_s1_register_name(char *dest, uint32_t opcode)
{
	get_register_name(dest, (opcode & OPCODE_S1_MASK) >> OPCODE_S1_SHIFT);
}

static const char *pixel_register_names[256] =
{
	[0] = "SrcBase",
	[1] = "SrcMode",
	[2] = "SrcMask",
	[3] = "Stride",
	[4] = "DstBase",
	[5] = "DstMode",
	[6] = "DstFmt",
	[7] = "PMask",
	[8] = "Pattern",
	[10] = "IPat",
	[12] = "PatMode",
	[13] = "PatOffset",
	[14] = "ScissorX",
	[15] = "ScissorY",
	[16] = "ZBase",
	[17] = "DitherOffset",
	[19] = "FGColor",
	[20] = "BGColor",
	[21] = "FogColor",
	[22] = "DstColor",
	[23] = "ChromaColor",
	[24] = "YUVContrast",
	[26] = "ChromaMask",
	[27] = "FGColorRGB",
	[28] = "Pick",
	[29] = "AlphaThres",
	[30] = "SpecColor",
	[31] = "Sync",
	[32] = "Tex4Pal[0]",
	[33] = "Tex4Pal[1]",
	[34] = "Tex4Pal[2]",
	[35] = "Tex4Pal[3]",
	[36] = "Tex4Pal[4]",
	[37] = "Tex4Pal[5]",
	[38] = "Tex4Pal[6]",
	[39] = "Tex4Pal[7]",

	[48] = "SrcFmt",
	[49] = "SrcFunc",
	[50] = "SrcFilter",
	[51] = "SrcColorNoPad",
	[52] = "SwapUV",
	[53] = "ChromaKey",
	[54] = "ZScissorEn",
	[55] = "SrcBGR",
	[56] = "UMask",
	[57] = "VMask",
	[58] = "SrcStride",
	[59] = "DstStride",
	[60] = "ZStride",
	[61] = "ChromaBlackYUV",
	[62] = "UClamp",
	[63] = "VClamp",
	[64] = "ALUMode",
	[65] = "BlendSrcFunc",
	[66] = "BlendDstFunc",
	[67] = "ZBufMode",
	[68] = "ZBufWrMode",
	[69] = "YUV2RGB",
	[70] = "BlendEnable",
	[71] = "DitherEnable",
	[72] = "FogEnable",
	[73] = "DstColorNoPad",
	[74] = "DstRdDisable",
	[75] = "DstBGR",
	[76] = "TranspReject",
	[80] = "PatLengthM1",
	[81] = "PatEnable",
	[82] = "PatOpaque",
	[83] = "SpecularEn"

};

static void get_pixel_register_name(char *dest, uint32_t opcode)
{
	int reg = (opcode & OPCODE_S1_MASK) >> OPCODE_S1_SHIFT;

	if (pixel_register_names[reg])
		strcpy(dest, pixel_register_names[reg]);
	else
		sprintf(dest, "%%%i", reg);
}

static void disassemble_opcode(uint32_t opcode, uint32_t addr)
{
	char pixel_reg_name[16];
	char dest_reg_name[16];
	char s2_reg_name[16];
	char s1_reg_name[16];
	uint8_t op = opcode >> 24;
	int s2 = (opcode & OPCODE_S2_MASK) >> OPCODE_S2_SHIFT;
	int s1 = (opcode & OPCODE_S1_MASK) >> OPCODE_S1_SHIFT;
	int32_t offset16 = (int32_t)(int16_t)((opcode & OPCODE_BRANCH_OFFSET_MASK) >> OPCODE_BRANCH_OFFSET_SHIFT);

	get_dest_register_name(dest_reg_name, opcode);
	get_s2_register_name(s2_reg_name, opcode);
	get_s1_register_name(s1_reg_name, opcode);

	if (!opcodes[op].name)
	{
		printf("<undef>");
		return;
	}
	
	if (!opcode)
	{
		printf("nop");
		return;
	}

	switch (opcodes[op].op_type)
	{
		case OP_TYPE_INTEGER:
		printf("%s\t%s, %s, %s", opcodes[op].name, dest_reg_name, s2_reg_name, s1_reg_name);
		break;

		case OP_TYPE_INTEGER_IMM:
		printf("%s\t%s, %s, #0x%x", opcodes[op].name, dest_reg_name, s2_reg_name, opcode & OPCODE_INT_IMM_MASK);
		break;

		case OP_TYPE_LOAD:
		printf("%s\t%s, %x(%s)", opcodes[op].name, dest_reg_name,
					((opcode & OPCODE_LOAD_OFFSET_MASK) >> OPCODE_LOAD_OFFSET_SHIFT) * opcodes[op].offset_mul,
					s1_reg_name);
		break;

		case OP_TYPE_STORE:
		printf("%s\t%x(%s), %s", opcodes[op].name,
					((opcode & OPCODE_STORE_OFFSET_MASK) >> OPCODE_STORE_OFFSET_SHIFT) * opcodes[op].offset_mul,
					s1_reg_name, s2_reg_name);
		break;

		case OP_TYPE_LOAD_IMM:
		printf("%s\t%s, #0x%x", opcodes[op].name, dest_reg_name, opcode & OPCODE_IMM_MASK);
		break;

		case OP_TYPE_SPRII:
		get_pixel_register_name(pixel_reg_name, opcode);
		printf("%s\t%s, 0x%04x", opcodes[op].name, pixel_reg_name, (opcode & OPCODE_SPRII_OFFSET_MASK) >> OPCODE_SPRII_OFFSET_SHIFT);
		break;

		case OP_TYPE_BRANCH:
		printf("%s\t%s, 0x%x", opcodes[op].name, s1_reg_name, (addr + 4 + offset16*4) & 0xffffff);
		break;

		case OP_TYPE_OTHER:
		switch (op)
		{
			case 0x0e: /*clip - S2 and S1 registers*/
			printf("clip\t%s, %s", s2_reg_name, opcode & OPCODE_INT_IMM_MASK);
			break;

			case 0x1e: case 0x2e: case 0x3e: /*clip - S2 and S1 registers*/
			printf("%s\t%s, %s", opcodes[op].name, s2_reg_name, s1_reg_name);
			break;

			case 0x40: case 0x41 : /*addif / subif - immediate shifted 16*/
			printf("%s\t%s, %s, #0x%x", opcodes[op].name, dest_reg_name, s2_reg_name, (opcode & OPCODE_INT_IMM_MASK) << 16);
			break;

			case 0x4f: /*spri - S1 = pixel register, S2 = source*/
			get_pixel_register_name(pixel_reg_name, opcode);
			printf("spri\t%s, %s", pixel_reg_name, s2_reg_name);
			break;

			case 0x52: /*abs - D and S1 registers*/
			case 0xc0: case 0xc1: case 0xc2: case 0xc3: /*getxy / getyx / getrg / getba - D and S1 registers*/
			printf("%s\t%s, %s", opcodes[op].name, dest_reg_name, s1_reg_name);
			break;

			case 0x5f: /*spr - S1 = indirect pixel register, S2 = source*/
			printf("spr\t(%s), %s", s1_reg_name, s2_reg_name);
			break;

			case 0x6b: /*getpc - D register but no other parameters*/
			printf("getpc\t%s", dest_reg_name);
			break;

			case 0x68: case 0x6a: /*rjmp / rjmpl - relative 24-bit address*/
			printf("%s\t0x%06x", opcodes[op].name, (addr + 4 + (opcode & 0x3fffff) * 4) & 0xffffff);
			break;

			case 0x6c: case 0x6e: /*jmp / jmpl - absolute 24-bit address*/
			printf("%s\t0x%06x", opcodes[op].name, (opcode & 0x3fffff) << 2);
			break;

			case 0x6d: /*halt*/
			printf("halt\t0x%04x", opcode & 0xffff);
			break;

			case 0x6f: /*jmprl - D and S1 registers*/
			printf("jmprl\t%s, (%s)", dest_reg_name, s1_reg_name);
			break;

			case 0x73: /*pre - load instruction without D register*/
			printf("%s\t%x(%s)", opcodes[op].name,
						((opcode & OPCODE_LOAD_OFFSET_MASK) >> OPCODE_LOAD_OFFSET_SHIFT) * opcodes[op].offset_mul,
						s1_reg_name);
			break;

			case 0xd0: /*step x/y*/
			if (!(s2 & 1))
				printf("step\tx, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			else
				printf("step\ty, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd1: /*step q*/
			printf("step\tq, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd2: /*step r/v*/
			if (!(s2 & 1))
				printf("step\tr, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			else
				printf("step\tv, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd3: /*step i/u*/
			if (!(s2 & 1))
				printf("step\ti, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			else
				printf("step\tu, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd4: /*step f*/
			printf("step\tf, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd5: /*step g/b*/
			if (!(s2 & 1))
				printf("step\tg, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			else
				printf("step\tb, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd6: /*step z/a*/
			if (!(s2 & 1))
				printf("step\tz, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			else
				printf("step\ta, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd7: /*step cnt*/
			printf("step\tcnt, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd8: /*step xy*/
			printf("step\txy, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xd9: /*step qu*/
			printf("step\tqu, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xda: /*step rv*/
			printf("step\trv, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xdb: /*step iv*/
			printf("step\tiv, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xdc: /*step zv*/
			printf("step\tzv, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xdd: /*step gb*/
			printf("step\tgb, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xde: /*step za*/
			printf("step\tza, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;

			case 0xdf: /*step cnt*/
			printf("step\tcnt, %s, %s, %s", dest_reg_name, s2_reg_name, s1_reg_name);
			break;
		}
	}
}


void verite_disassemble(uint32_t *data, uint32_t addr, uint32_t size)
{
//	size = 0x1000;
	while (size)
	{
		uint32_t opcode = be_to_le(*data++);

		printf("   %08x:\t%08x\t", addr, opcode);
		disassemble_opcode(opcode, addr);
		printf("\n");

		addr += 4;
		size -= 4;
	//	break;
	}
}