.SUFFIXES: .cpp .o
CXX ?= g++
CXXFLAGS ?= -g -std=c++20 -Wall # remove -Wall in complete version so no unnecesarry warnings
EXEC ?= main.cpp
OBJS ?=  main.cpp conditions.h bigInt.h sha512.h MerkleTree.h AES.h block.h wallet.h ui.h

${EXEC}: main.cpp
        ${CXX} ${CXXFLAGS} -o ${EXEC} main.o

.cpp.o:
        ${CXX} ${CXXFLAGS} -c $<

main.o: ${OBJS}
        ${CXX} -c main.cpp

clean:
        rm -f ${EXEC} ${OBJS}

run: ${EXEC}
        ./${EXEC} ${ARGS}
