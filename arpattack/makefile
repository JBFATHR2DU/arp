objects= get_ifi_info.o parse_hostnetworkmask.o getgateway.o get_printMAC.o 
compiled-objects=error.o wrapsock.o wrapunix.o 
CFLAG=-g
ifdef DEBUG
  CFLAG+= -DDEBUG
endif
ifdef HASHCONFLICT
  CFLAG+=-DHASHCONFLICT
endif
ifdef 	MATCH
  CFLAG+=-DMATCHDEBUG
endif
ifdef 	VM
  CFLAG+=-DVMDEBUG
endif
CC=gcc
WALL=-Wall

arpattack:$(objects) arpattack.c arpattack.h selfdefine.h unpifi.h jhash.h
	gcc $(CFLAG) $(WALL) arpattack.c $(objects) $(compiled-objects) -lpthread -o arpattack
	cp arpattack /bin/
	
$(objects) : %.o : %.c unpifi.h
	$(CC) -c $(CFLAG) $<	-o $@ 
	
#清除中间生成的所有目标文件
.PHONY :clean
clean:
	rm -f arpattack /bin/arpattack $(objects)

