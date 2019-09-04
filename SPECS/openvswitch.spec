%define _release 2.2.3.5%{?dist}
Name: openvswitch
Summary: Virtual switch
URL: http://www.openvswitch.org/
Version: 2.5.3
License: ASL 2.0 and GPLv2
Release: %{_release}

Source0: https://code.citrite.net/rest/archive/latest/projects/XSU/repos/%{name}/archive?at=refs%2Ftags%2Fv%{version}&prefix=%{name}-%{version}&format=tar.gz#/%{name}-%{version}.tar.gz
Source1: openvswitch-ipsec.service
Source2: ovs-monitor-ipsec

Patch0: 0001-vswitchd-Introduce-mtu_request-column-in-Interface.patch
Patch1: 0002-bridge-Honor-mtu_request-when-port-is-added.patch
Patch2: 0003-ofproto-Honor-mtu_request-even-for-internal-ports.patch
Patch3: 0001-mcast-snooping-Flush-ports-mdb-when-VLAN-configurati.patch
Patch4: 0002-mcast-snooping-Avoid-segfault-for-vswitchd.patch
Patch5: 0001-ofproto-Fix-wrong-datapath-flow-with-same-in_port-an.patch
Patch6: CA-72973-hack-to-strip-temp-dirs-from-paths.patch
Patch7: CP-15129-Convert-to-use-systemd-services.patch
Patch8: CA-78639-dont-call-interface-reconfigure-anymore.patch
Patch9: CA-141390-dont-read-proc-cpuinfo-if-running-on-xenserver.patch
Patch10: CA-151580-disable-recirculation-if-lacp-not-nego.patch
Patch11: CA-153718-md5-verification-dvsc.patch
Patch12: CP-9895-Add-originator-to-login_with_password-xapi-call.patch
Patch13: CP-13181-add-dropping-of-fip-and-lldp.patch
Patch14: use-old-db-port-6632-for-dvsc.patch
Patch15: CA-243975-Fix-openvswitch-service-startup-failure.patch
Patch16: CP-23098-Add-IPv6-multicast-snooping-toggle.patch
Patch17: CA-265107-When-enable-igmp-snooping-cannot-receive-ipv6-multicast-traffic.patch
Patch18: CP-23607-Send-learning-pkt-when-non-act-bond-slave-failed.patch
Patch19: CP-23607-inject-multicast-query-msg-on-bond-port.patch

Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XS/repos/openvswitch.pg/archive?format=tar&at=2.2.3#/openvswitch.patches.tar) = 240ee58d6325e73a469485317af17cc4cfec76ec
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/openvswitch/archive?at=refs%2Ftags%2Fv2.5.3&prefix=openvswitch-2.5.3&format=tar.gz#/openvswitch-2.5.3.tar.gz) = e954fdbfa97a1a357a4dcfff80f5bd916a2eb647

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
BuildRequires: glibc-static, kernel-devel, openssl, openssl-devel, openssl-static, python
BuildRequires: autoconf, automake, libtool

# XCP-ng patches
Patch1000: openvswitch-2.5.3-fix-log-rotation.XCP-ng.patch

%if %undefined module_dir
%define module_dir updates
%endif
%if %undefined modules_suffix
%define modules_suffix modules
%endif

# Only build the modules for a 3.10 kernel.
%define build_modules %(if echo %{kernel_version} | grep -q "^3\.10\."; then
                            echo 1
                        else
                            echo 0
                        fi)

%if %build_modules
%define with_linux --with-linux=/lib/modules/%{kernel_version}/build
%endif

%description
The vswitch provides standard network bridging functions augmented with
support for the OpenFlow protocol for remote per-flow control of
traffic.

%prep
%autosetup -p1

%build
sh boot.sh
%configure --enable-ssl --without-pcre --without-ncurses --with-logdir=/var/log --with-dbdir=/run/openvswitch %{?with_linux} \
           LDFLAGS="$LDFLAGS -Wl,-rpath=/lib64/citrix"

%{?cov_wrap} %{__make} %{_smp_mflags}

%install
rm -rf %{buildroot}
%{?cov_wrap} %{__make} install DESTDIR=%{buildroot}

%if %build_modules
%{?cov_wrap} %{__make} INSTALL_MOD_PATH=%{buildroot} modules_install
# mark modules executable so that strip-to-file can strip them
find %{buildroot}/lib/modules/%{kernel_version} -name "*.ko" -type f | xargs chmod u+x
%endif

install -d -m 755 %{buildroot}/var/lib/openvswitch
install -d -m 755 %{buildroot}/var/log/openvswitch
install -d -m 755 %{buildroot}/var/xen/openvswitch

install -d -m 755 %{buildroot}/%{_sysconfdir}/openvswitch

install -d -m 755 %{buildroot}/%{_sysconfdir}/sysconfig
install -m 755 xenserver/usr_share_openvswitch_scripts_sysconfig.template \
         %{buildroot}/%{_sysconfdir}/sysconfig/openvswitch

install -d -m 755 %{buildroot}/%{_sysconfdir}/logrotate.d
install -m 644 xenserver/etc_logrotate.d_openvswitch \
         %{buildroot}/%{_sysconfdir}/logrotate.d/openvswitch

install -d -m 755 %{buildroot}/%{_sysconfdir}/xapi.d/plugins
install -m 755 xenserver/etc_xapi.d_plugins_openvswitch-cfg-update \
         %{buildroot}/%{_sysconfdir}/xapi.d/plugins/openvswitch-cfg-update

install -d -m 755 %{buildroot}/%{_datadir}/openvswitch
install -m 644 vswitchd/vswitch.ovsschema \
         %{buildroot}/%{_datadir}/openvswitch/vswitch.ovsschema

install -d -m 755 %{buildroot}/%{_datadir}/openvswitch/scripts
install -m 755 xenserver/usr_share_openvswitch_scripts_ovs-xapi-sync \
         %{buildroot}/%{_datadir}/openvswitch/scripts/ovs-xapi-sync
install -m 755 xenserver/usr_share_openvswitch_scripts_ovs-start \
         %{buildroot}/%{_datadir}/openvswitch/scripts/ovs-start

install -d -m 755 %{buildroot}/%{_unitdir}
install -m 644 xenserver/usr_lib_systemd_system_openvswitch.service \
         %{buildroot}/%{_unitdir}/openvswitch.service
install -m 644 xenserver/usr_lib_systemd_system_openvswitch-xapi-sync.service \
         %{buildroot}/%{_unitdir}/openvswitch-xapi-sync.service

install -d -m 755 %{buildroot}/%{_libdir}/xsconsole/plugins-base
install -m 644 xenserver/usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py \
         %{buildroot}/%{_libdir}/xsconsole/plugins-base/XSFeatureVSwitch.py

#install python/compat/uuid.py %{buildroot}/%{_datadir}/openvswitch/python
#install python/compat/argparse.py %{buildroot}/%{_datadir}/openvswitch/python


# Get rid of stuff we don't want to make RPM happy.
(cd "$RPM_BUILD_ROOT" && rm -f usr/lib64/lib*)

install -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/openvswitch-ipsec.service
install -m 755 %{SOURCE2} %{buildroot}%{_datadir}/openvswitch/scripts/ovs-monitor-ipsec

#%check
#make check

%post
%systemd_post openvswitch.service
%systemd_post openvswitch-xapi-sync.service

%preun
%systemd_preun openvswitch.service
%systemd_preun openvswitch-xapi-sync.service

%postun
%systemd_postun openvswitch.service
%systemd_postun openvswitch-xapi-sync.service

%files
#%doc COPYING README
%config %{_sysconfdir}/sysconfig/openvswitch
%config %{_sysconfdir}/logrotate.d/openvswitch
%{_sysconfdir}/xapi.d/plugins/openvswitch-cfg-update
%dir %{_sysconfdir}/openvswitch
%dir /run/openvswitch
%dir %{_var}/xen/openvswitch
%dir %{_var}/lib/openvswitch
%dir %{_var}/log/openvswitch
%{_sysconfdir}/bash_completion.d/ovs-appctl-bashcomp.bash
%{_sysconfdir}/bash_completion.d/ovs-vsctl-bashcomp.bash
%{_bindir}/ovs-docker
%{_bindir}/ovs-testcontroller
%{_bindir}/ovs-benchmark
%{_bindir}/ovs-appctl
%{_bindir}/ovs-dpctl
%{_bindir}/ovs-dpctl-top
%{_bindir}/ovs-l3ping
%{_bindir}/ovs-ofctl
%{_bindir}/ovs-pcap
%{_bindir}/ovs-tcpundump
%{_bindir}/ovs-vlan-test
%{_bindir}/ovs-vsctl
%{_bindir}/ovsdb-client
%{_bindir}/ovsdb-tool
%{_bindir}/ovs-test
%{_sbindir}/ovs-bugtool
%{_sbindir}/ovs-vswitchd
%{_sbindir}/ovsdb-server
%{_datadir}/openvswitch/bugtool-plugins/kernel-info/openvswitch.xml
%{_datadir}/openvswitch/bugtool-plugins/network-status/openvswitch.xml
%{_datadir}/openvswitch/bugtool-plugins/system-configuration.xml
%{_datadir}/openvswitch/bugtool-plugins/system-configuration/openvswitch.xml
%{_datadir}/openvswitch/bugtool-plugins/system-logs/openvswitch.xml
%{_datadir}/openvswitch/python/ovs/__init__.py*
%{_datadir}/openvswitch/python/ovs/daemon.py*
%{_datadir}/openvswitch/python/ovs/db/__init__.py*
%{_datadir}/openvswitch/python/ovs/db/data.py*
%{_datadir}/openvswitch/python/ovs/db/error.py*
%{_datadir}/openvswitch/python/ovs/db/idl.py*
%{_datadir}/openvswitch/python/ovs/db/parser.py*
%{_datadir}/openvswitch/python/ovs/db/schema.py*
%{_datadir}/openvswitch/python/ovs/db/types.py*
%{_datadir}/openvswitch/python/ovs/unixctl/__init__.py*
%{_datadir}/openvswitch/python/ovs/unixctl/client.py*
%{_datadir}/openvswitch/python/ovs/unixctl/server.py*
%{_datadir}/openvswitch/python/ovs/dirs.py*
%{_datadir}/openvswitch/python/ovs/fatal_signal.py*
%{_datadir}/openvswitch/python/ovs/json.py*
%{_datadir}/openvswitch/python/ovs/jsonrpc.py*
%{_datadir}/openvswitch/python/ovs/ovsuuid.py*
%{_datadir}/openvswitch/python/ovs/poller.py*
%{_datadir}/openvswitch/python/ovs/process.py*
%{_datadir}/openvswitch/python/ovs/reconnect.py*
%{_datadir}/openvswitch/python/ovs/socket_util.py*
%{_datadir}/openvswitch/python/ovs/stream.py*
%{_datadir}/openvswitch/python/ovs/timeval.py*
%{_datadir}/openvswitch/python/ovs/util.py*
%{_datadir}/openvswitch/python/ovs/vlog.py*
%{_datadir}/openvswitch/python/ovs/version.py*
#%{_datadir}/openvswitch/python/argparse.py*
#%{_datadir}/openvswitch/python/uuid.py*
%{_datadir}/openvswitch/vswitch.ovsschema
%{_datadir}/openvswitch/scripts/ovs-lib
%{_datadir}/openvswitch/scripts/ovs-bugtool-*
%{_datadir}/openvswitch/scripts/ovs-ctl
%{_datadir}/openvswitch/scripts/ovs-save
%{_datadir}/openvswitch/scripts/ovs-start
%{_datadir}/openvswitch/scripts/ovs-xapi-sync
%{_mandir}/man1/ovsdb-client.1.gz
%{_mandir}/man1/ovsdb-tool.1.gz
%{_mandir}/man1/ovsdb-server.1.gz
%{_mandir}/man5/ovs-vswitchd.conf.db.5.gz
%{_mandir}/man8/ovs-appctl.8.gz
%{_mandir}/man8/ovs-dpctl.8.gz
%{_mandir}/man8/ovs-dpctl-top.8.gz
%{_mandir}/man8/ovs-ofctl.8.gz
%{_mandir}/man1/ovs-pcap.1.gz
%{_mandir}/man1/ovs-tcpundump.1.gz
%{_mandir}/man8/ovs-vlan-test.8.gz
%{_mandir}/man8/ovs-vsctl.8.gz
%{_mandir}/man8/ovs-vswitchd.8.gz
%{_mandir}/man1/ovs-benchmark.1.gz
%{_mandir}/man8/ovs-bugtool.8.gz
%{_mandir}/man8/ovs-ctl.8.gz
%{_libdir}/xsconsole/plugins-base/
%{_unitdir}/openvswitch.service
%{_unitdir}/openvswitch-xapi-sync.service

%exclude /usr/include/openflow/*
%exclude /usr/include/openvswitch/*
%exclude /usr/lib64/pkgconfig/libofproto.pc
%exclude /usr/lib64/pkgconfig/libopenvswitch.pc
%exclude /usr/lib64/pkgconfig/libovsdb.pc
%exclude /usr/lib64/pkgconfig/libsflow.pc
%exclude /usr/share/man/man8/ovs-testcontroller.8.gz
%exclude /usr/share/openvswitch/ovn-nb.ovsschema
%exclude /usr/share/openvswitch/ovn-sb.ovsschema
%exclude /usr/share/openvswitch/scripts/ovn-ctl
%exclude %{_bindir}/ovs-l3ping
%exclude %{_bindir}/ovs-parse-backtrace
%exclude %{_bindir}/ovs-pki
%exclude %{_bindir}/vtep-ctl
%exclude %{_bindir}/ovn-controller
%exclude %{_bindir}/ovn-controller-vtep
%exclude %{_bindir}/ovn-docker-overlay-driver
%exclude %{_bindir}/ovn-docker-underlay-driver
%exclude %{_bindir}/ovn-nbctl
%exclude %{_bindir}/ovn-northd
%exclude %{_bindir}/ovn-sbctl
%exclude %{_sbindir}/ovs-vlan-bug-workaround
%exclude %{_mandir}/man5/ovn-nb.5.gz
%exclude %{_mandir}/man5/ovn-sb.5.gz
%exclude %{_mandir}/man5/vtep.5.gz
%exclude %{_mandir}/man7/ovn-architecture.7.gz
%exclude %{_mandir}/man8/ovs-l3ping.8.gz
%exclude %{_mandir}/man8/ovs-parse-backtrace.8.gz
%exclude %{_mandir}/man8/ovs-vlan-bug-workaround.8.gz
%exclude %{_mandir}/man8/ovs-pki.8.gz
%exclude %{_mandir}/man8/ovs-test.8.gz
%exclude %{_mandir}/man8/vtep-ctl.8.gz
%exclude %{_mandir}/man8/ovn-controller-vtep.8.gz
%exclude %{_mandir}/man8/ovn-controller.8.gz
%exclude %{_mandir}/man8/ovn-ctl.8.gz
%exclude %{_mandir}/man8/ovn-nbctl.8.gz
%exclude %{_mandir}/man8/ovn-northd.8.gz
%exclude %{_mandir}/man8/ovn-sbctl.8.gz
%exclude %{_datadir}/openvswitch/python/ovstest
%exclude %{_datadir}/openvswitch/scripts/ovs-check-dead-ifs
%exclude %{_datadir}/openvswitch/scripts/ovs-vtep
%exclude %{_datadir}/openvswitch/vtep.ovsschema

%if %build_modules

%package modules
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XS/repos/openvswitch.pg/archive?format=tar&at=2.2.3#/openvswitch.patches.tar) = 240ee58d6325e73a469485317af17cc4cfec76ec
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/openvswitch/archive?at=refs%2Ftags%2Fv2.5.3&prefix=openvswitch-2.5.3&format=tar.gz#/openvswitch-2.5.3.tar.gz) = e954fdbfa97a1a357a4dcfff80f5bd916a2eb647
Summary: Open vSwitch kernel module
Release: %{_release}
Version: %(echo "%{kernel_version}" | tr - .)
License: GPLv2
Provides: %{name}-modules = %{kernel_version}
%if 0%{?fedora} >= 17 || 0%{?rhel} >= 7
Requires(post): /usr/sbin/depmod
Requires(postun): /usr/sbin/depmod
%else
Requires(post): /sbin/depmod
Requires(postun): /sbin/depmod
%endif

%description modules
Open vSwitch Linux kernel module compiled against kernel version
%{kernel_version}.

%files modules
%defattr(-,root,root)
/lib/modules/%{kernel_version}/extra/*.ko
%exclude /lib/modules/%{kernel_version}/modules.*

%post modules
/sbin/depmod -a %{kernel_version}

%postun modules
/sbin/depmod -a %{kernel_version}

%endif


%package ipsec
Summary: Open vSwitch IPsec package
Requires: %{name} = %{version}-%{release}
Requires: libreswan >= 3.26

%description ipsec
Provides an Open vSwitch extension allowing to use encrypted
tunnels using IPsec.

%files ipsec
%{_unitdir}/openvswitch-ipsec.service
%{_datadir}/openvswitch/scripts/ovs-monitor-ipsec

%post ipsec
%systemd_post openvswitch-ipsec.service

%preun ipsec
%systemd_preun openvswitch-ipsec.service

%postun ipsec
%systemd_postun openvswitch-ipsec.service

%changelog
* Wen Sep 04 2019 Benjamin Reis <benjamin.reis@vates.fr> - 2.5.3-2.2.3.5
- Add openvswitch-ipsec package

* Mon Feb 25 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 2.5.3-2.2.3.3
- Fix log rotation for /var/log/ovsdb-server.log: do not rotate the .gz files themselves.

* Wed Nov 21 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 2.5.3-2.2.3.2.xcp
- Fix log rotation
- https://github.com/xcp-ng/xcp/issues/100

* Mon Apr 23 2018 Simon Rowe <simon.rowe@citrix.com> - 2.5.3-2.2.3
- CA-288424: Fix sporadic output of incoming packets back to the same port

* Mon Apr 16 2018 Simon Rowe <simon.rowe@citrix.com> - 2.5.3-2.2.2
- CA-281351: Stop services that require network before openvswitch

* Fri Sep 22 2017 Yang Qian <yang.qian@citrix.com> - 2.5.3-2.2.1
- REQ-230 Multicast support

