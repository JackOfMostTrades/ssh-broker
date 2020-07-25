all: ssh-broker-pkcs11.so

clean:
	rm -f ssh-broker-pkcs11.so

test: test.c ssh-broker-pkcs11.c
	gcc -fPIC -Wall -I /usr/include/opencryptoki ssh-broker-pkcs11.c test.c -o test -lcrypto
	./test

ssh-broker-pkcs11.so: ssh-broker-pkcs11.c
	gcc -shared -fPIC -Wall -I /usr/include/opencryptoki ssh-broker-pkcs11.c -o ssh-broker-pkcs11.so -lcrypto
