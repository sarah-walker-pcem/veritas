CC   = gcc
CFLAGS = -g3

OBJ = elf.o veritas.o verite_disasm.o

veritas.exe: $(OBJ)
	$(CC) $(OBJ) -o "veritas.exe"

%.o : %.c
	$(CC) $(CFLAGS) -c $<
