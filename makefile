.SUFFIXES: .c .o
CXX ?= g++
CXXFLAGS ?= -g -std=c++20 -Wall # remove -Wall in complete version so no unnecesarry warnings
EXEC ?= main
OBJS ?= main.C conditions.h bigInt.h sha512.h MerkleTree.h AES.h block.h wallet.h ui.h

${EXEC}: main.o
        ${CXX} ${CXXFLAGS} -o ${EXEC} main.o

.c.o:
        ${CXX} ${CXXFLAGS} -c $<

main.o: ${OBJS}
        ${CXX} -c main.C

clean:
        rm -f ${EXEC} ${OBJS}

run: ${EXEC}
        ./{EXEC} ${ARGS}