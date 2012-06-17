##
##  Makefile -- Build procedure for sample mod_resource_manager Apache module
##	  MATSUMOTO, Ryosuke
##

# target module source
TARGET=mod_resource_manager.c

#   the used tools
APXS=/usr/sbin/apxs
APACHECTL=/etc/init.d/httpd
#APXS=/usr/local/apache2.4/bin/apxs
#APACHECTL=/usr/local/apache2.4/bin/apachectl

#   additional user defines, includes and libraries
#DEF=-DSYSLOG_NAMES
INC=-I. -I/usr/local/src/mruby/src -I/usr/local/src/mruby/include
LIB=-lm /usr/local/src/mruby/lib/libmruby.a -lm /usr/local/src/mruby/mrblib/mrblib.o
WC=-Wc,-std=c99,-Wall,-Werror-implicit-function-declaration
CFLAGS = $(INC) $(LIB) $(WC)

#   the default target
all: mod_resource_manager.so

#   compile the DSO file
mod_resource_manager.so: $(TARGET)
	$(APXS) -c $(DEF) $(CFLAGS) $(TARGET)

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n 'resource_manager' .libs/mod_resource_manager.so

#   cleanup
clean:
	-rm -rf .libs *.o *.so *.lo *.la *.slo *.loT

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

