CXX=g++-12
RM=rm -f
CPPFLAGS=--std=c++2b -Werror -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Wnull-dereference -Wold-style-cast -Wdouble-promotion -Wshadow

SRCS=security.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: lab

lab: $(OBJS)
	$(CXX) $(CPPFLAGS) -o lab $(OBJS)

# Build all C++ files
depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CXX) $(CPPFLAGS) -MM $^>>./.depend

# Clean compiled C++ files
clean:
	$(RM) $(OBJS) *~ .depend lab
 

include .depend