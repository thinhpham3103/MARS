BUILD ?= ../build
ALL := demo_she demo_ascon demo_dice_she
ALLB := $(ALL:%=$(BUILD)/%)

all: $(BUILD) $(ALLB)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: %.c
	gcc -c $< -o $@

$(BUILD)/mars_she.o: hw_she.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

$(BUILD)/mars_ascon.o: hw_ascon.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

demo_a_obj := $(patsubst %,$(BUILD)/%,mars_ascon.o hw_ascon.o demo.o)
$(BUILD)/demo_ascon: $(demo_a_obj)
	gcc -o $@ $^ ../ascon/LibAscon-master/src/libascon.a -lpthread

$(BUILD)/demo_she: $(BUILD)/mars_she.o $(BUILD)/hw_she.o $(BUILD)/demo.o
	gcc -o $@ $^ ../aes/aes.o -lpthread

$(BUILD)/demo_dice_she: $(BUILD)/mars_she.o $(BUILD)/hw_she.o $(BUILD)/demo_dice.o
	gcc -o $@ $^ ../aes/aes.o -lpthread

clean:
	rm $(BUILD)/*.o $(ALLB)
	rmdir $(BUILD)

