all: ssh-broker-pkcs11.so

clean:
	rm -f ssh-broker-pkcs11.so

test: ssh_broker_pkcs11_test ssh_broker_client_test
ssh_broker_pkcs11_test: ssh_broker_pkcs11_test.c ssh-broker-pkcs11.so
	gcc -g -Wall -I /usr/include/opencryptoki ssh_broker_pkcs11_test.c -o ssh_broker_pkcs11_test -ldl
	./ssh_broker_pkcs11_test
ssh_broker_client_test: ssh_broker_client.c ssh_broker_client_test.c base64.c ssh_broker_client.c
	gcc -g -Wall -I /usr/include/opencryptoki ssh_broker_client.c ssh_broker_client_test.c base64.c -o ssh_broker_client_test -lcurl -ljson-c -lcrypto
	./ssh_broker_client_test

ssh-broker-pkcs11.so: ssh-broker-pkcs11.c base64.c ssh_broker_client.c
	gcc -shared -fPIC -Wall -I /usr/include/opencryptoki ssh-broker-pkcs11.c base64.c ssh_broker_client.c -o ssh-broker-pkcs11.so -lcrypto -ljson-c -lcurl
