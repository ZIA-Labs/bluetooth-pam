


mac:
	gcc -dynamiclib -fPIC -fno-stack-protector src/zia_auth.c -o zia_auth.so -lpam
