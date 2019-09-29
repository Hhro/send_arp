EXEC = send_arp
CPP = g++

$(EXEC): main.o
	$(CPP) -o $(EXEC) main.o -L ../lib -lxpkt -lpthread -lpcap

%.o: %.cpp
	$(CPP) -c $< -o $@ -I../include

clean:
	rm main.o send_arp