Name: monit
Summary: Process monitor and restart utility
Version: 5.2.3
Release: 1
Source: http://www.mmonit.com/monit/dist/%{name}-%{version}.tar.gz
Group: Utilities/Console
URL: http://www.mmonit.com/monit/
BuildRoot: %{_tmppath}/%{name}-buildroot
License: GPL
BuildRequires: flex
BuildRequires: bison
BuildRequires: openssl-devel

%description
Monit is a utility for managing and monitoring processes,
files, directories and filesystems on a Unix system. Monit conducts
automatic maintenance and repair and can execute meaningful causal
actions in error situations.

%prep
%setup

%build
%{configure}
make

%install
if [ -d %{buildroot} ] ; then
  rm -rf %{buildroot}
fi

make BINDIR=%{buildroot}%{_bindir} MANDIR=%{buildroot}%{_mandir}/man1 install

mkdir -p %{buildroot}/etc/init.d
install -m 600 monitrc %{buildroot}/etc/monitrc
install -m 755 contrib/rc.monit %{buildroot}/etc/init.d/%{name}

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
   /etc/init.d/%{name} stop >/dev/null 2>&1
   /sbin/chkconfig --del %{name}
fi

%clean
if [ -d %{buildroot} ] ; then
  rm -rf %{buildroot}
fi

%files
%defattr(-,root,root)
%doc CHANGES.txt COPYING LICENSE README README.SSL
%config /etc/monitrc
%config /etc/init.d/%{name}
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1.gz

%changelog
* Thu Sep 16 2010 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.2

* Thu Feb 18 2010 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.1.1

* Sat Jan 09 2010 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.1

* Thu May 28 2009 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.0.3

* Thu May 7 2009 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.0.2

* Wed Apr 22 2009 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.0.1

* Sun Apr 13 2008 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-5.0

* Mon Nov 06 2007 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.10.1

* Mon Nov 05 2007 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.10

* Wed Feb 19 2007 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.9

* Sun Mar 05 2006 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.7

* Wed Sep 19 2005 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.6

* Wed Oct 19 2004 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.4

* Wed Nov 04 2003 Martin Pala <martinp@tildeslash.com>
- Fixed the bad path to monit binary in startup script. Thanks to Ben Ciceron
  for report of the problem.

* Wed Oct 27 2003 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.1

* Wed Sep 23 2003 Martin Pala <martinp@tildeslash.com>
- change the description

* Wed Mar 07 2003 Martin Pala <martinp@tildeslash.com>
- Upgraded to monit-4.0
- Updated documentation list
- Changed use of monit.conf file to default monitrc ( => monit could find it )
- Use monitrc and rc.monit from default monit distribution

* Wed Jul 10 2002 Rory Toma <rory@digeo.com>
- Upgraded to monit-2.4.3

* Mon Feb 05 2001 Clinton Work <work@scripty.com>
- Upgraded to monit 1.2
- Use chkconfig to add monit to the rc.d startup scripts
- Use the example monitrc instead of my custom monit.conf
- Fixed the monit homepage URL

* Thu Feb 01 2001 Clinton Work <work@scripty.com>
- Create the inital spec file
- Created a sample config file and a rc startup script
