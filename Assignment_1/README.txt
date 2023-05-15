gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0


For both RSA and DH:
	Use the command 'make' to create the executable from the source files. Use
	the command 'make clean' to remove the executable and the object files.


For DH:
	The program is run as described in the assignment instructions. GMP has been
	used for the arithmetic computations here as well, because otherwise the
	program was very vulnerable to cause wrong results due to overflows.

For RSA:
	The program is run as described in the assignment instructions. For the
	key-pair generation, the two prime numbers that are needed are given from
	the user (through stdin) as described in the assignment instructions in
	section "Key generation". Note: one way to automate this task is to redirect
	stdin or to pipe. Each prime must be followed by a '\n' character. There is
	a demo file named "plaintext.txt".


(I hope that)
The comments inside the source codes are pretty adequate and explanatory so as
the steps for each implementation could be easily understood without paying much
attention to the code.
