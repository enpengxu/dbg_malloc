#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
	for(int k=0; k<10; k++) {
		char * p = malloc(sizeof(char)*10);
		for (int i=0; i<9; i++) {
			p[i] = 'a' + i;
		}
		p[10] = 0;
		fprintf(stderr, "str %d: %p \n", k, p);
	}
	pid_t pid = fork();
	if (pid == 0) {
		for(int k=0; k<10; k++) {
			char * p = malloc(sizeof(char)*10);
			for (int i=0; i<9; i++) {
				p[i] = 'a' + i;
			}
			p[10] = 0;
			fprintf(stderr, "str %d: %p \n", k, p);
		}
	}

	return 0;
}
