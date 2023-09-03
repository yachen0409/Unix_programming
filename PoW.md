# Proof of Work (PoW)

Some of the challenge servers are secured using a proof of work challenge. In this case, you have to solve the challenge first. A PoW challenge can be implemented in several different forms. This document introduces the PoW challenge implemented for labs in this course.

Our PoW challenge sends you a string **P**, and you have to respond with a *base64-encoded* string **S** so that the hex digest of $sha1(P+decode(S))$ has at least 6 leading zeros (that is, 24 bits of zeros).

# C-based Implementation

If you don't want to implement the PoW solver alone, you may use our sample implementation, which contains a simple base64 implementation ([view](https://up23.zoolab.org/code.html?file=pow/base64.c)|[download](https://up23.zoolab.org/pow/base64.c)) and a PoW solver ([view](https://up23.zoolab.org/code.html?file=pow/solve.c)|[download](https://up23.zoolab.org/pow/solve.c)). To compile the solver, you need an additional linker option ``-lcrypto``. 

# Python-based Implementation

If you have `pwntools` installed, you may access our challenge server using the script `pow.py`([view](https://up23.zoolab.org/code.html?file=pow/pow.py)|[download](https://up23.zoolab.org/pow/pow.py)). The instructions for installing `pwntools` can be found [here](https://md.zoolab.org/s/EleTCdAQ5).

You may play with our PoW server using the sample codes and tools. The sample PoW server can be connected using `nc`

```
nc up23.zoolab.org 10330
```
