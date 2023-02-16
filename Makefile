all: wireview.cpp
	gcc -g -w -o wireview wireview.cpp -lpcap -lstdc++
	
wireview: wireview.cpp
	gcc -g -w -o wireview wireview.cpp -lpcap -lstdc++
	

clean: wireview.cpp
	rm -f wireview
	gcc -g -w -o wireview wireview.cpp -lpcap -lstdc++
