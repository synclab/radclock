# This make file creates the .ko module for retrieving the vitual counter through syscall.

.PATH: ${.CURDIR}/../../kern

KMOD    =  radclock
SRCS    =  radclock.c

SRCS+=	opt_radclock.h

.if !defined(KERNBUILDDIR)
opt_radclock.h:
	echo "#define RADCLOCK 1" > opt_radclock.h
.endif

.include <bsd.kmod.mk>
