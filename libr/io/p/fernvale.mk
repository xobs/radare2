OBJ_FERNVALE=io_fernvale.o

STATIC_OBJ+=${OBJ_FERNVALE}
TARGET_FERNVALE=io_fernvale.${EXT_SO}
ALL_TARGETS+=${TARGET_FERNVALE}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_FERNVALE}: ${OBJ_FERNVALE}
	${CC_LIB} $(call libname,io_fernvale) ${CFLAGS} -o ${TARGET_FERNVALE} ${OBJ_FERNVALE} ${LINKFLAGS}
