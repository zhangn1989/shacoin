CC = g++  
LINK = g++  
CFLAGS = -g -Wall -rdynamic -I../include 
LFLAGS = -lcrypto -lssl
LIBS =

SRC_DIR = . 
SFIX = .cpp

SOURCES := $(foreach x,${SRC_DIR},\
       $(wildcard  \
       $(addprefix  ${x}/*,${SFIX}) ) )
#SOURCES = $(wildcard *.cpp)  
OBJECTS = $(patsubst %.cpp, %.o, $(SOURCES))  
TARGET = shacoin

first: all

%.o: %.cpp 
	$(CC) -c $(CFLAGS) $(LFLAGS) -o $@ $<  
			  
all: $(TARGET)  

$(TARGET): $(OBJECTS)
	@echo $(TARGET)
	$(LINK) $(LIBS) $(OBJECTS) $(CFLAGS) $(LFLAGS) -o ../$(TARGET)

.PHONY: clean

clean:  
	rm -f $(OBJECTS) ../$(TARGET)  
