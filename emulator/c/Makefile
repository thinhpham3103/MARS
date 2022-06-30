BUILD ?= ../build
ALL := demo mars_ascon.so mars_she.so mars_sha2.so mars_sha3.so disp

ALLB := $(ALL:%=$(BUILD)/%)

all: $(BUILD) $(ALLB)

OSL3DIR ?= ../openssl/openssl-openssl-3.0
ifneq ($(wildcard $(OSL3DIR)), )
    OSL3INC := -I $(OSL3DIR)/include -Wno-deprecated-declarations
    OSL3LIB := $(OSL3DIR)/libcrypto.so
else
    OSL3INC := -Wno-deprecated-declarations
    OSL3LIB := -lcrypto
endif

$(BUILD)/disp: hw_sha2.h dispatcher.c $(BUILD)/vget.o $(BUILD)/mars_sha3.so
	gcc -o $@ -include $^ $(BUILD)/libtinycbor.so

$(BUILD):
	mkdir $@

$(BUILD)/hw_she.o: hw_she.c hw_she.h
	gcc -fpic -o $@ -c $<

$(BUILD)/aes.o: ../aes/aes.c
	gcc -fpic -o $@ -c $<

$(BUILD)/mars_she.o: hw_she.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_she.so: $(BUILD)/mars_she.o $(BUILD)/hw_she.o $(BUILD)/aes.o
	gcc -shared -o $@ $^ $(BUILD)/libtinycbor.so

##############################################################

$(BUILD)/hw_sha2.o: hw_sha2.c hw_sha2.h
	gcc -fpic -o $@ -c $< $(OSL3INC)

$(BUILD)/mars_sha2.o: hw_sha2.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_sha2.so: $(BUILD)/mars_sha2.o $(BUILD)/hw_sha2.o
	gcc -shared -o $@ $^ $(OSL3LIB)

##############################################################

$(BUILD)/hw_sha3.o: hw_sha3.c hw_sha3.h
	gcc -fpic -o $@ -c $< $(OSL3INC)

$(BUILD)/mars_sha3.o: hw_sha3.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_sha3.so: $(BUILD)/mars_sha3.o $(BUILD)/hw_sha3.o
	gcc -shared -o $@ $^ $(OSL3LIB)

##############################################################

$(BUILD)/hw_ascon.o: hw_ascon.c hw_ascon.h
	gcc -fpic -o $@ -c $<

$(BUILD)/mars_ascon.o: hw_ascon.h mars.c mars.h
	gcc -o $@ -include $< -fpic -c mars.c

$(BUILD)/mars_ascon.so: $(BUILD)/mars_ascon.o $(BUILD)/hw_ascon.o ../ascon/LibAscon-1.2.0/src/ascon.so
	gcc -shared -o $@ $^

##############################################################

$(BUILD)/%.o: %.c mars.h
	gcc -o $@ -c $<

$(BUILD)/api.o: api.h

$(BUILD)/demo: $(BUILD)/demo.o $(BUILD)/api.o $(BUILD)/vget.o $(BUILD)/libtinycbor.so
	gcc -o $@ $^

clean:
	rm $(BUILD)/*.o $(ALLB)
	rmdir $(BUILD)

