Name: radclock 
Summary: Robust Absolute and Difference Clock
Version: _RADCLOCK_VERSION_ 
Release: 0
License: Non-Free 
Group: System Environment/Daemons
URL: http://www.synclab.org/radclock/
#Source0: %{name}-%{version}.tar.gz
#Patch0: foo-1.0-iconfix.patch
#Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root
Buildroot: %{_tmppath}/%{name}-%{version}-root
Requires: libpcap, libnl
#Prereq: something
# So far do not indicate a version number for libnl since we look for future official release. 
# Anyway we are the top level maintainer, so we will think of it when we will distribute this.
BuildPrereq: autoconf, automake, libnl-devel, libpcap-devel >= 0.8

%description 
Robust Absolute and Difference Clock
The included daemon and library use the selected clock source to provide a robust 
feed-forward synchronisation algorithm.

%prep 
#%setup -q -n ${radclock_rpm_release}
#%setup -q
#%patch0 -p1 -b .iconfix
cd $radclock_rpm_release
aclocal
autoheader
automake -a
autoconf


%build 
cd $radclock_rpm_release
%configure 
make

%install 
cd $radclock_rpm_release
rm -fr %{buildroot}

%makeinstall
mkdir -p %{buildroot}/%{_docdir}/radclock/
cp COPYING NEWS README ChangeLog copyright %{buildroot}/%{_docdir}/radclock/
mkdir -p %{buildroot}/etc/init.d
cp redhat/radclock.init %{buildroot}/etc/init.d/radclock
chmod u+x %{buildroot}/etc/init.d/radclock

%clean 
rm -fr %{buildroot}

%post
# Install the sym links for the init.d script
if [ -x /usr/lib/lsb/install_initd ]; then
  /usr/lib/lsb/install_initd /etc/init.d/radclock
elif [ -x /sbin/chkconfig ]; then
  /sbin/chkconfig --add radclock 
else
   for i in 3 4 5; do
        ln -sf /etc/init.d/radclock /etc/rc.d/rc${i}.d/S95radclock
   done
   for i in 1 2 6; do
        ln -sf /etc/init.d/radclock /etc/rc.d/rc${i}.d/K60radclock
   done
fi
# Start the radclock
/sbin/service radclock start


%preun 
if [ "$1" = 0 ]; then 
  /sbin/service radclock stop > /dev/null 2>&1
  if [ -x /usr/lib/lsb/remove_initd ]; then
    /usr/lib/lsb/remove_initd /etc/init.d/radclock
  elif [ -x /sbin/chkconfig ]; then
    /sbin/chkconfig --del radclock 
  else
    rm -f /etc/rc.d/rc?.d/???radclock
  fi
fi



%postun 
#if [ "$1" -ge "1" ]; then 
#  /sbin/service foo condrestart > /dev/null 2>&1 
#  /sbin/ldconfig 
#fi

%files 
%defattr(-,root,root) 
%{_bindir}/* 
/etc/init.d/radclock
%{_libdir}/* 
%{_includedir}/* 
%{_mandir}/* 
#%{_datadir}/* 
%{_docdir}/*


#%changelog 

