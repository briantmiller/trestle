%global selinuxtype targeted
%global modulename trestle

Name:           trestle
Version:        0.1
Release:        1%{?dist}
Summary:        CNI and Netavark plugin attaching rootless containers to host bridges
License:        GPL-3.0-or-later
URL:            https://example.com/trestle
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig(json-c)
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel
BuildRequires:  bzip2

Requires:       nftables
Recommends:     aardvark-dns
Recommends:     (%{name}-selinux if selinux-policy-%{selinuxtype})
%{?systemd_requires}

%description
trestle lets rootless Podman containers (through Netavark) and Kubernetes
pods (through CNI) attach to a bridge on the host. An unprivileged plugin
binary validates each request and hands it, together with the container's
network namespace, to the trestled daemon, which checks the caller against
per-network user and group lists, creates the bridge and veth pair, assigns
addresses, publishes host names (/etc/hosts, dnsmasq, aardvark-dns) and
manages nftables filtering and masquerading.

%package selinux
Summary:        SELinux policy module for trestle
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
%{?selinux_requires}

%description selinux
SELinux policy module that confines trestled in the trestled_t domain and
allows container runtimes to use the trestle socket.

%prep
%autosetup

%build
# exports CFLAGS/LDFLAGS; the Makefile adds its own required flags
%set_build_flags
%make_build \
    PREFIX=%{_prefix} SBINDIR=%{_sbindir} LIBEXECDIR=%{_libexecdir} \
    SYSCONFDIR=%{_sysconfdir} LOCALSTATEDIR=%{_localstatedir}/lib
make selinux
bzip2 -9 selinux/%{modulename}.pp

%install
make install DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} SBINDIR=%{_sbindir} LIBEXECDIR=%{_libexecdir} \
    SYSCONFDIR=%{_sysconfdir} LOCALSTATEDIR=%{_localstatedir}/lib \
    UNITDIR=%{_unitdir} TMPFILESDIR=%{_tmpfilesdir} MANDIR=%{_mandir} \
    DOCDIR=%{_docdir}/%{name}
install -D -m 0644 selinux/%{modulename}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -D -m 0644 selinux/%{modulename}.if \
    %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{modulename}.if

%check
%set_build_flags
make check \
    PREFIX=%{_prefix} SBINDIR=%{_sbindir} LIBEXECDIR=%{_libexecdir} \
    SYSCONFDIR=%{_sysconfdir} LOCALSTATEDIR=%{_localstatedir}/lib

%post
%tmpfiles_create %{_tmpfilesdir}/trestle.conf
%systemd_post trestled.service

%preun
%systemd_preun trestled.service

%postun
%systemd_postun_with_restart trestled.service

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
    %selinux_relabel_post -s %{selinuxtype}
fi

%files
%license LICENSE
%doc %{_docdir}/%{name}
%{_sbindir}/trestled
%dir %{_libexecdir}/trestle
%{_libexecdir}/trestle/trestle
%{_libexecdir}/netavark/trestle
%{_libexecdir}/cni/trestle
%dir %{_sysconfdir}/trestle
%dir %{_sysconfdir}/trestle/conf.d
%dir %{_sysconfdir}/trestle/hooks
%config(noreplace) %{_sysconfdir}/trestle/trestle.conf
%{_sysconfdir}/trestle/conf.d/README
%{_unitdir}/trestled.service
%{_tmpfilesdir}/trestle.conf
%dir %attr(0700,root,root) %{_localstatedir}/lib/trestle
%{_mandir}/man5/trestle.conf.5*
%{_mandir}/man8/trestle.8*
%{_mandir}/man8/trestled.8*

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
%ghost %verify(not md5 size mode mtime) %{_localstatedir}/lib/selinux/%{selinuxtype}/active/modules/200/%{modulename}

%changelog
* Fri Oct 23 2026 Brian Miller <brianthomasmiller@gmail.com> - 0.1-1
- Initial package
