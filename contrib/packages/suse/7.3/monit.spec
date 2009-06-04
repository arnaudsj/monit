#
#   $Id: monit.spec,v 1.12 2007/01/03 09:31:01 martinp Exp $
#
# neededforbuild autoconf bind9-utils bison flex glibc glibc-devel make patch perl
# usedforbuild   autoconf bind9-utils bison flex glibc glibc-devel gzip make patch perl yacc

Distribution:	SuSE 7.3
Group: 		System Environment/Daemons
Vendor:		Kourentis und Brüeggemann Informationssysteme GbR, Bonn, Germany
Packager:	oppel@kbis.de

Name:		monit
Version:	3.1
Release:	0
Copyright:	(C) 2000-2007 by Contributors to the monit codebase, GNU GPL

Provides:	monit
#Requires:
#Obsolete:

Url:		http://www.tildeshlash.com/monit/
Source:		http://www.tildeshlash.com/monit/dist/%{name}-%{version}.tar.gz
Source1:	%{name}.init
Source2:	%{name}.rc.config
#Patch:

Summary: Monit is a daemon monitoring daemon (DMD).

Prefix: 	/usr
%define docdir	/usr/share/doc/packages/%{name}
%define mandir 	/usr/share/man

BuildRoot:	/var/tmp/build-root-%{name}

%description
monit is a simple daemon process to restart processes if they die.
It can also check tcp and udp ports to make sure that they are responding.

SuSE series:	sec

%prep
rm -rf $RPM_BUILD_ROOT 
mkdir $RPM_BUILD_ROOT
%setup -q
#%patch -p1

%build
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix} --mandir=%{mandir}
make -j 2
%install
mkdir -p $RPM_BUILD_ROOT/etc
cp $RPM_BUILD_DIR/%{name}-%{version}/monitrc $RPM_BUILD_ROOT/etc/monit.conf
mkdir -p $RPM_BUILD_ROOT/etc/init.d
cp $RPM_SOURCE_DIR/%{name}.init $RPM_BUILD_ROOT/etc/init.d/%{name}
for i in 2 3 5; do
    mkdir -p $RPM_BUILD_ROOT/etc/init.d/rc$i.d
    ln -sf ../%{name} $RPM_BUILD_ROOT/etc/init.d/rc$i.d/K02monit
    ln -sf ../%{name} $RPM_BUILD_ROOT/etc/init.d/rc$i.d/S20monit
done
mkdir -p $RPM_BUILD_ROOT/etc/rc.config.d
cp $RPM_SOURCE_DIR/%{name}.rc.config $RPM_BUILD_ROOT/etc/rc.config.d/
mkdir -p $RPM_BUILD_ROOT/usr/sbin
ln -sf ../../etc/init.d/%{name} $RPM_BUILD_ROOT/usr/sbin/rc%{name}
mkdir -p $RPM_BUILD_ROOT%{docdir}
for i in CHANGES.txt CONTRIBUTORS COPYING FAQ.txt LICENSE PACKAGES README README.SSL STATUS; do
    cp -p $RPM_BUILD_DIR/%{name}-%{version}/$i $RPM_BUILD_ROOT%{docdir}/
done
cp -pR $RPM_BUILD_DIR/%{name}-%{version}/doc $RPM_BUILD_ROOT%{docdir}/
cp -pR $RPM_BUILD_DIR/%{name}-%{version}/contrib $RPM_BUILD_ROOT%{docdir}/
make DESTDIR=$RPM_BUILD_ROOT install
strip $RPM_BUILD_ROOT%{prefix}/bin/%{name}

cd $RPM_BUILD_ROOT

#find . -type d | sed '1,2d;s,^\.,\%attr(-\,root\,root) \%dir ,' > $RPM_BUILD_DIR/file.list.%{name}
#find . -type f | sed 's,^\.,\%attr(-\,root\,root) ,' >> $RPM_BUILD_DIR/file.list.%{name}
#find . -type l | sed 's,^\.,\%attr(-\,root\,root) ,' >> $RPM_BUILD_DIR/file.list.%{name}
#cat $RPM_BUILD_DIR/file.list.%{name} | sed 's+/man1/monit\.1+/man1/monit\.1\.gz+' > $RPM_BUILD_DIR/file.list.%{name}.tmp
#mv -v $RPM_BUILD_DIR/file.list.%{name}.tmp $RPM_BUILD_DIR/file.list.%{name}

%clean
rm -rf $RPM_BUILD_ROOT
rm -f  $RPM_BUILD_DIR/file.list.%{name}

#%files -f ../file.list.%{name}
#%defattr(-,root,root,0755)
%files
%attr(0600,root,root) %config(noreplace) /etc/monit.conf
%attr(0740,root,root) %config /etc/init.d/monit
%attr(0644,root,root) %config(noreplace) /etc/rc.config.d/monit.rc.config
%attr(0550,root,root) /usr/bin/monit
%attr(0644,root,root) %doc /usr/share/man/man1/monit.1.gz
%attr(-,root,root) /etc/init.d/rc2.d/K02monit
%attr(-,root,root) /etc/init.d/rc2.d/S20monit
%attr(-,root,root) /etc/init.d/rc3.d/K02monit
%attr(-,root,root) /etc/init.d/rc3.d/S20monit
%attr(-,root,root) /etc/init.d/rc5.d/K02monit
%attr(-,root,root) /etc/init.d/rc5.d/S20monit
%attr(-,root,root) /usr/sbin/rcmonit
%attr(0755,root,root) %dir %{docdir}
%attr(0644,root,root) %doc %{docdir}/CHANGES.txt
%attr(0644,root,root) %doc %{docdir}/CONTRIBUTORS
%attr(0644,root,root) %doc %{docdir}/COPYING
%attr(0644,root,root) %doc %{docdir}/FAQ.txt
%attr(0644,root,root) %doc %{docdir}/LICENSE
%attr(0644,root,root) %doc %{docdir}/PACKAGES
%attr(0644,root,root) %doc %{docdir}/README
%attr(0644,root,root) %doc %{docdir}/README.SSL
%attr(0644,root,root) %doc %{docdir}/STATUS
%attr(0755,root,root) %dir %{docdir}/doc
%attr(0644,root,root) %dir %{docdir}/doc/monit.html
%attr(0755,root,root) %dir %{docdir}/doc/api-docs
%attr(0644,root,root) %dir %{docdir}/doc/api-docs/*
%attr(0755,root,root) %dir %{docdir}/contrib
%attr(0644,root,root) %doc %{docdir}/contrib/*

%post
#cd /etc/init.d
#
# this one is for upgrades:
test -w /etc/monit.conf && chmod 600 /etc/monit.conf

%changelog -n monit
* Tue Oct 08 2002 - oppel@kbis.de
- update to 3.1 in advance
- added README.SSL
* Mon Sep 23 2002 - oppel@kbis.de
- fixed: noreplace monit.rc.config
* Tue Sep 17 2002 - oppel@kbis.de
- update to 3.0
- added complete doc directory
- added complete contrib directory
- changed monit.conf permissions to 600
* Mon Aug 26 2002 - oppel@kbis.de
- update to 2.5.1
- added PACKAGES to doc directory
* Sat Jul 13 2002 - oppel@kbis.de
- 2.5 release build
* Fri Jul 12 2002 - oppel@kbis.de
- update to 2.5 (beta test)
* Tue Jul 09 2002 - oppel@kbis.de
- minor fix
* Mon Jul 08 2002 - oppel@kbis.de
- update to 2.4.3
- added documentation to docdir
* Fri May 31 2002 - oppel@kbis.de
- initial packageing (version 2.4)
