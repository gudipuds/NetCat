all: netcat_part.c
	gcc -lssl -o netcat_part netcat_part.c

clean:
	\rm -rf *.o
