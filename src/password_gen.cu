#include <string.h>

// password generator
char *CHARSET = "abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"0123456789";
unsigned char CHARSET_LEN;

// initialise pw generator
// counter: array of char, stores a binary count of the current password
// pw: array of char, stores a string containing the current password
// TODO: see if a for loop and divider is faster (for x=0 to (num_combinations/charset_len), for y=0 to charset_len) or smth lk tht
void password_init(int pwlen, int *counter, char *pw)
{
	// reset counter and string buffer
	memset(counter, 0, pwlen);
	memset(pw, CHARSET[0], pwlen);
	// set null terminator on password
	pw[pwlen] = 0;
	// initialise charset length
	CHARSET_LEN = strlen(CHARSET);
}

// go to the next password
// params are the same as for password_init
int password_next(int pwlen, int *counter, char *pw)
{
	int i;

	// increment least significant character
	for (i=(pwlen-1); i>=0; i--) {
		// increment to next character
		counter[i]++;
		// hit end of charset?
		if (counter[i] == CHARSET_LEN) {
			// yep, reset to zero
			counter[i] = 0;
			pw[i] = CHARSET[0];
		} else {
			// no rollover, update string and break
			pw[i] = CHARSET[counter[i]];
			break;
		}
	}

	// did last char roll over?
	return (i < 0);
}


