gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0


For access type: The user cannot delete files using fopen and fwrite (and there
		is not further explanation about deletion in assignment instructions) so
the access type does not take the value 3.


There are some files for demonstration with the following modes: (those files are not included in the github project, but they can be created by the user)

-r--r--r-- 1 john john 0 Nov 29 21:42 file_0
--w--w--w- 1 john john 6 Nov 29 21:22 file_1
-rw-rw-rw- 1 john john 6 Nov 29 21:22 file_2
-rw-rw-r-- 1 john john 6 Nov 29 21:22 file_3
-r--r--r-- 1 john john 6 Nov 29 21:22 file_4
-r--r--r-- 1 john john 6 Nov 29 21:22 file_5
-r--r--r-- 1 john john 6 Nov 29 21:22 file_6
-r--r--r-- 1 john john 6 Nov 29 21:22 file_7
--w--w---- 1 john john 6 Nov 29 21:22 file_8
--w--w---- 1 john john 6 Nov 29 21:22 file_9

file_3 will not exist for creation demonstration.


Encryption has not been implemented.

Everything else works as described in assignment instructions.
