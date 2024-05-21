all: netfilter_test

netfilter_test: netfilter_test.o
	gcc -o netfilter_test netfilter_test.c -lnetfilter_queue -g

clean:
	rm -f netfilter_test



