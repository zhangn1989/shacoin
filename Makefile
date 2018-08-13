CC = g++  
LINK = g++  
CFLAGS = -g -Wall -rdynamic -I./ 
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
	$(CC) -c $(CFLAGS) -o $@ $<  
			  
all: $(TARGET)  

$(TARGET): $(OBJECTS)
	@echo $(TARGET)
	$(LINK) $(CFLAGS) $(LIBS) -o $(TARGET) $(OBJECTS)   

.PHONY: clean

clean:  
	rm -f $(OBJECTS) $(TARGET)  
