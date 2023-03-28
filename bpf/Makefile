bpf.o: bpf.c
	clang \
		-target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-O2 \
		-g \
		-o $@ \
		-c $^

.PHONY: clean
clean:
	rm *.o
