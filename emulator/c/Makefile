BUILD ?= ../build
ALL := demo mars_ascon.so mars_she.so mars_null.so
ALLB := $(ALL:%=$(BUILD)/%)

all: $(BUILD) $(ALLB)

$(BUILD):
	mkdir $@

$(BUILD)/hw_she.o: hw_she.c hw_she.h
	gcc -fpic -o $@ -c $<

$(BUILD)/aes.o: ../aes/aes.c
	gcc -fpic -o $@ -c $<

$(BUILD)/mars_she.o: hw_she.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_she.so: $(BUILD)/mars_she.o $(BUILD)/hw_she.o $(BUILD)/aes.o
	gcc -shared -o $@ $^




$(BUILD)/hw_ascon.o: hw_ascon.c hw_ascon.h
	gcc -fpic -o $@ -c $<

$(BUILD)/mars_ascon.o: hw_ascon.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_ascon.so: $(BUILD)/mars_ascon.o $(BUILD)/hw_ascon.o ../ascon/LibAscon-master/src/ascon.so
	gcc -shared -o $@ $^

$(BUILD)/mars_null.so: mars_null.c
	gcc -shared -o $@ -fpic $<

$(BUILD)/%.o: %.c mars.h
	gcc -o $@ -c $<

$(BUILD)/demo: $(BUILD)/demo.o $(BUILD)/mars_null.so
	gcc -o $@ $^

clean:
	rm $(BUILD)/*.o $(ALLB)
	rmdir $(BUILD)

