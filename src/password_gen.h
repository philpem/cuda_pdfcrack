#ifndef H__PASSWORD_GEN_H
#define H__PASSWORD_GEN_H

// initialise pw generator
// counter: array of char, stores a binary count of the current password
// pw: array of char, stores a string containing the current password
// TODO: see if a for loop and divider is faster (for x=0 to (num_combinations/charset_len), for y=0 to charset_len) or smth lk tht
void password_init(int pwlen, int *counter, char *pw);

// go to the next password
// params are the same as for password_init
int password_next(int pwlen, int *counter, char *pw);

/*
 * example -- will loop over all possible 3-character passwords
 *
	int counter[32];
	char str[32];
	password_init(3, counter, str);
	str[3] = 0;

	do {
		printf("%s\n", str);
		x = password_next(3, counter, str);
	} while (!x);
*/


#endif // H__PASSWORD_GEN_H
