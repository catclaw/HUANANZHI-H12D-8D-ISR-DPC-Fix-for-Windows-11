CXX ?= g++
TARGET ?= latencydoctor.exe

CXXFLAGS ?= -std=gnu++17 -O2 -Wall -Wextra -municode -DUNICODE -D_UNICODE
LDFLAGS ?= -static -lpsapi -lversion -lsetupapi -lcfgmgr32 -lshlwapi -ladvapi32

.PHONY: all clean

all: $(TARGET)

$(TARGET): latencydoctor.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
