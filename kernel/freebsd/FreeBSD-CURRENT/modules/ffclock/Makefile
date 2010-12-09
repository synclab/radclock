# This make file creates the .ko module for retrieving the vitual counter through syscall.

.PATH: ${.CURDIR}/../../kern

KMOD    =  radclock
SRCS    =  radclock.c

SRCS+=	opt_ffclock.h

.if !defined(KERNBUILDDIR)
opt_ffclock.h:
	echo "#define FFCLOCK 1" > opt_ffclock.h
.endif

.include <bsd.kmod.mk>
