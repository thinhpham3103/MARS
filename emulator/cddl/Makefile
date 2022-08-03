BUILD ?= ../build

all: $(BUILD) $(BUILD)/mars_cbor.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/mars_decoder.c: mars.cddl
	zcbor -c $^ code -d -t Mars_Command --oc $@ --oh $(BUILD)/mars_decoder.h

$(BUILD)/mars_encoder.c: mars.cddl
	zcbor -c $^ code -e -t Mars_Response --oc $@ --oh $(BUILD)/mars_encoder.h

$(BUILD)/mars_encoder.o: $(BUILD)/mars_encoder.c
	gcc -O2 -c -I$(BUILD) -I./zcbor/include -o $@ $^

$(BUILD)/mars_decoder.o: $(BUILD)/mars_decoder.c
	gcc -O2 -c -I$(BUILD) -I./zcbor/include -o $@ $^

$(BUILD)/mars_cbor.o: mars_cbor.c
	gcc -O2 -c -I$(BUILD) -I./zcbor/include -o $@ $^

$(BUILD)/zcbor_common.o: ./zcbor/src/zcbor_common.c
	gcc -O2 -c -I./zcbor/include -o $@ $^

$(BUILD)/zcbor_decode.o: ./zcbor/src/zcbor_decode.c
	gcc -O2 -c -I./zcbor/include -o $@ $^

$(BUILD)/zcbor_encode.o: ./zcbor/src/zcbor_encode.c
	gcc -O2 -c -I./zcbor/include -o $@ $^

$(BUILD)/mars_cbor.a: $(BUILD)/zcbor_encode.o $(BUILD)/zcbor_decode.o $(BUILD)/zcbor_common.o $(BUILD)/mars_encoder.o $(BUILD)/mars_decoder.o $(BUILD)/mars_cbor.o
	ar cr $(BUILD)/mars_cbor.a $^

clean:
	rm $(BUILD)/*
	rmdir $(BUILD)

