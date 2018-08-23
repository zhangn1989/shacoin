DIRS = block holePunching

all: subdirs  
  
.PHONY: subdirs clean  
  
subdirs: $(DIRS) 
	for dir in $(DIRS); do  make -C $$dir; done
			  
clean:  
	@echo $(DIRS)  
	for dir in $(DIRS); do  make clean -C $$dir; done
