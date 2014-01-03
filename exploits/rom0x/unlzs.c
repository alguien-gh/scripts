/*
 * unlzs.c
 *
 *  Created on: 10/10/2013
 *      Author: alguien
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

char get_bit(char *data, int *offset, int *index) {
	char abyte;
	abyte = (data[*index] & (1 << (7 - *offset))) >> (7 - *offset);
	(*offset)++;
	if (*offset == 8) {
		(*index)++;
		*offset = 0;
	}
	return abyte;
}

char *get_nbits(int nbits, char *data, int *offset, int *index) {
	char *bytes;
	int nbytes = (nbits % 8) ? nbits / 8 + 1 : nbits / 8;
	int boffset = (nbits % 8) ? 8 - nbits % 8 : 0;
	int bindex = 0;

	bytes = malloc(sizeof(char) * nbytes);
	bzero(bytes, sizeof(char) * nbytes);

	int i;
	char bit;
	for (i = 0; i < nbits; i++) {
		bit = get_bit(data, offset, index);

		bytes[bindex] = bytes[bindex] | ((bit << 7) >> boffset);
		boffset++;
		if (boffset == 8) {
			bindex++;
			boffset = 0;
		}
	}

	return bytes;
}

int is_endmarker(char *data, int *offset, int *index) {
	int end = 0;
	int offset_tmp = *offset, index_tmp = *index;
	char *bytes = get_nbits(2, data, offset, index);

	if (bytes[0] == (char) 3) {
		bytes = get_nbits(7, data, offset, index);

		if (bytes[0] == (char) 0) {
			end = 1;
		}
	}

	*offset = offset_tmp;
	*index = index_tmp;
	return end;
}

char *uncompress_lzs(char *data) {
	int data_offset = 0, data_index = 0;
	char abyte, *bytes;

	char *history = malloc(sizeof(char) * 2048);
	int hindex = 0;

	bzero(history, sizeof(char) * 2048);

	while (1) {
		abyte = get_bit(data, &data_offset, &data_index);

		if (abyte == (char) 0) {
			// raw pattern
			bytes = get_nbits(8, data, &data_offset, &data_index);
			history[hindex] = bytes[0];
			hindex++;

		} else {
			// string pattern

			int sp_offset = 0;

			abyte = get_bit(data, &data_offset, &data_index);

			if (abyte == (char) 0) {
				// offset > 127
				bytes = get_nbits(11, data, &data_offset, &data_index);
				char aux = bytes[0];
				bytes[0] = bytes[1];
				bytes[1] = aux;
				sp_offset = *((short *) bytes);

			} else {
				// offset <= 127
				bytes = get_nbits(7, data, &data_offset, &data_index);
				sp_offset = *((char *) bytes);
			}

			int sp_length = 0;

			bytes = get_nbits(2, data, &data_offset, &data_index);
			if (bytes[0] != 3) {
				// length <= 4
				sp_length = ((int) bytes[0]) + 2;
			} else {
				bytes = get_nbits(2, data, &data_offset, &data_index);

				if (bytes[0] != 3) {
					// length <= 7
					sp_length = ((int) bytes[0]) + 5;
				} else {
					// length > 7
					int n = 0;
					while (1) {
						bytes = get_nbits(4, data, &data_offset, &data_index);
						if (bytes[0] == (char) 15) {
							n++;
						} else {
							break;
						}
					}
					sp_length = (n * 15) + ((int) bytes[0]) + 8;
				}
			}

			// copiar patron
			int count = 0;
			for (count = 0; count < sp_length; count++) {
				history[hindex] = history[hindex - sp_offset];
				//printf("%c\n", history[hindex]);
				hindex++;
			}
		}

		if (is_endmarker(data, &data_offset, &data_index) == 1) {
			// end marker
			break;
		}

	}

	return history;
}


int main(int argc, char **argv) {

	if( argc == 0) {
		printf("Modo de uso: %s <data.lzs>\n", argv[0]);
		return -1;
	}

	FILE *file = NULL;

	file = fopen(argv[1], "rb");
	if (!file) {
		printf("Error. No se puede abrir el archivo.\n");
		return -1;
	}

	char *data = malloc(sizeof(char) * 2048);
	fread(data, sizeof(char), 2048, file);
	fclose(file);

	char *uncompress = uncompress_lzs(data);
	int count;
	for (count = 0; count < 2048; count++) {
		printf("%c", uncompress[count]);
	}

	return 0;
}

