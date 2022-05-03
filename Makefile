all:	
	cd module ; make
	cd utilities ; make

module:
	cd module
	make clean
	make
	make reload

utilities:
	cd utilities
	make

clean:
	cd module ; make clean
	cd utilities ; make clean
