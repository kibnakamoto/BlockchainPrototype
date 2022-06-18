.SUFFIXES: .cpp .o
CXX ?= g++
CXXFLAGS ?= -g -std=c++20 -Wall # cxx flags for both clang and gcc
EXEC ?= main.cpp
OBJS ?=  main.cpp conditions.h bigint.h sha512.h merkletree.h aes.h block.h wallet.h ui.h
BINS ?= main.o

# TODO: make -Wall optional with sub command
# IMPORTANT:
# echo "make run ARGS="command-name" for running code with arguement"

main: ${BINS}
	${CXX} ${CXXFLAGS} -o main ${BINS}

main.o: ${OBJS}
	${CXX} ${CXXFLAGS} -c ${EXEC}

.cpp.o:
	${CXX} ${CXXFLAGS} -c $<

clean:
	rm -rf ${BINS} main

run: ${EXEC}
	clang++ ${CXXFLAGS} ${EXEC} -o main
	./main ${ARGS}
