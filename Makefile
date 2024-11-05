build:
	gcc -Wall -Wextra -std=c99 sfl.c -o sfl

run_sfl: sfl
	./sfl

pack:
	zip -FSr 315CA_DimitrieConstantin_Tema1.zip README Makefile *.c README

clean:
	rm -f $(TARGETS)

.PHONY: pack clean