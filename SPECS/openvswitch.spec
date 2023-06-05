%global package_speccommit a26d7fec8b64898ee6dc2ad34cf6b3481a4d3222
%global usver 2.5.3
%global xsver 2.3.13
%global xsrel %{xsver}%{?xscount}%{?xshash}
%global package_srccommit refs/tags/v2.5.3

# Control whether we build with the address sanitizer.
# Default enabled: (to override: --without asan)
#%%define with_asan  %%{?_without_asan: 0} %%{?!_without_asan: 1}
# Default disabled: (to override: --with asan)
%define with_asan  %{?_with_asan: 1} %{?!_with_asan: 0}

Name: openvswitch
Summary: Virtual switch
URL: http://www.openvswitch.org/
Version: 2.5.3
License: ASL 2.0 and GPLv2
Release: %{?xsrel}.2%{?dist}
Source0: openvswitch-2.5.3.tar.gz

# XCP-ng additional sources
Source1: openvswitch-ipsec.service
Source2: ovs-monitor-ipsec

Patch0: 0001-vswitchd-Introduce-mtu_request-column-in-Interface.patch
Patch1: 0002-bridge-Honor-mtu_request-when-port-is-added.patch
Patch2: 0003-ofproto-Honor-mtu_request-even-for-internal-ports.patch
Patch3: 0001-mcast-snooping-Flush-ports-mdb-when-VLAN-configurati.patch
Patch4: 0002-mcast-snooping-Avoid-segfault-for-vswitchd.patch
Patch5: 0001-lacp-enable-bond-slave-immediately-after-lacp-attach.patch
Patch6: 0001-mirror-Allow-concurrent-lookups.patch
Patch7: 0001-ofproto-Fix-wrong-datapath-flow-with-same-in_port-an.patch
Patch8: 0001-bond-send-learning-pkg-when-non-active-slave-failed.patch
Patch9: 0002-LACP-Check-active-partner-sys-id.patch
Patch10: 0001-configure-Check-for-more-specific-function-to-pull-i.patch
Patch11: 0001-flow-Support-extra-padding-length.patch
Patch12: 0001-bond-Honor-updelay-and-downdelay-when-LACP-is-in-use.patch
Patch13: 0001-bond-Fix-LACP-fallback-to-active-backup-when-recirc-.patch
Patch14: 0001-bond-Remove-executable-bit-from-bond.c.patch
Patch15: 0001-lacp-Avoid-packet-drop-on-LACP-bond-after-link-up.patch
Patch16: 0001-lacp-report-desync-in-ovs-threads-enabling-slave.patch
Patch17: 0001-ofproto-bond-Improve-admissibility-debug-readability.patch
Patch18: CA-72973-hack-to-strip-temp-dirs-from-paths.patch
Patch19: CP-15129-Convert-to-use-systemd-services.patch
Patch20: CA-78639-dont-call-interface-reconfigure-anymore.patch
Patch21: CA-141390-dont-read-proc-cpuinfo-if-running-on-xenserver.patch
Patch22: CA-153718-md5-verification-dvsc.patch
Patch23: CP-9895-Add-originator-to-login_with_password-xapi-call.patch
Patch24: CP-13181-add-dropping-of-fip-and-lldp.patch
Patch25: use-old-db-port-6632-for-dvsc.patch
Patch26: CA-243975-Fix-openvswitch-service-startup-failure.patch
Patch27: CP-23098-Add-IPv6-multicast-snooping-toggle.patch
Patch28: CA-265107-When-enable-igmp-snooping-cannot-receive-ipv6-multicast-traffic.patch
Patch29: 0001-xenserver-fix-Python-errors-in-Citrix-changes.patch
Patch30: 0002-O3eng-applied-patch-on-top-of-the-NSX-OVS.patch
Patch31: 0003-update-bridge-fail-mode-settings-when-bridge-comes-up.patch
Patch32: CP-23607-inject-multicast-query-msg-on-bond-port.patch
Patch33: mlockall-onfault.patch
Patch34: hide-logrotate-script-error.patch

# XCP-ng patches
Patch1000: openvswitch-2.5.3-CVE-2023-1668.backport.patch
Patch1001: openvswitch-2.5.3-comment-failing-tests.XCP-ng.patch

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
BuildRequires: openssl, openssl-devel, python
BuildRequires: autoconf, automake, libtool
%if %{with_asan}
BuildRequires: libasan
%endif
%{?_cov_buildrequires}

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
BuildRequires: kernel-devel
%define with_linux --with-linux=/lib/modules/%{kernel_version}/build
%endif

%description
The vswitch provides standard network bridging functions augmented with
support for the OpenFlow protocol for remote per-flow control of
traffic.

%prep
%autosetup -p1
%{?_cov_prepare}

%build
sh boot.sh

%if %{with_asan}
# Extend RPM's defaults to include address sanitizer
CFLAGS="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -fsanitize=address"
CXXFLAGS="$CFLAGS"
LDFLAGS="-Wl,-z,relro -fsanitize=address"
export CFLAGS CXXFLAGS LDFLAGS
%endif

%configure --enable-ssl --without-pcre --without-ncurses --with-logdir=/var/log/openvswitch --with-dbdir=/run/openvswitch %{?with_linux}

%{?_cov_wrap} %{__make} %{_smp_mflags}

%install
rm -rf %{buildroot}
%{?_cov_wrap} %{__make} install DESTDIR=%{buildroot}

%if %build_modules
%{?_cov_wrap} %{__make} INSTALL_MOD_PATH=%{buildroot} modules_install
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

#install python/compat/uuid.py %{buildroot}/%{_datadir}/openvswitch/python
#install python/compat/argparse.py %{buildroot}/%{_datadir}/openvswitch/python

# Get rid of stuff we don't want to make RPM happy.
(cd "$RPM_BUILD_ROOT" && rm -f usr/lib64/lib*)

%{?_cov_install}

# XCP-ng: ipsec
install -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/openvswitch-ipsec.service
install -m 755 %{SOURCE2} %{buildroot}%{_datadir}/openvswitch/scripts/ovs-monitor-ipsec

%check
make check TESTSUITEFLAGS="-j%(nproc)"

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
%{_sbindir}/ovs-vlan-bug-workaround
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
#%%{_datadir}/openvswitch/python/argparse.py*
#%%{_datadir}/openvswitch/python/uuid.py*
%{_datadir}/openvswitch/vswitch.ovsschema
%{_datadir}/openvswitch/scripts/ovs-lib
%{_datadir}/openvswitch/scripts/ovs-bugtool-*
%{_datadir}/openvswitch/scripts/ovs-check-dead-ifs
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
%{_mandir}/man8/ovs-vlan-bug-workaround.8.gz
%{_mandir}/man8/ovs-vlan-test.8.gz
%{_mandir}/man8/ovs-vsctl.8.gz
%{_mandir}/man8/ovs-vswitchd.8.gz
%{_mandir}/man1/ovs-benchmark.1.gz
%{_mandir}/man8/ovs-bugtool.8.gz
%{_mandir}/man8/ovs-ctl.8.gz
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
%exclude %{_mandir}/man5/ovn-nb.5.gz
%exclude %{_mandir}/man5/ovn-sb.5.gz
%exclude %{_mandir}/man5/vtep.5.gz
%exclude %{_mandir}/man7/ovn-architecture.7.gz
%exclude %{_mandir}/man8/ovs-l3ping.8.gz
%exclude %{_mandir}/man8/ovs-parse-backtrace.8.gz
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
%exclude %{_datadir}/openvswitch/scripts/ovs-vtep
%exclude %{_datadir}/openvswitch/vtep.ovsschema

%{?_cov_results_package}

%if %build_modules

%package modules
Summary: Open vSwitch kernel module
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
* Mon Jun 05 2023 David Morel <david.morel@vates.fr> - 2.5.3-2.3.13.2
- Backport fix for CVE-2023-1668: Remote traffic denial of service via crafted packets with IP proto 0
- Comment out tests that fail
- Enable make check in spec file

* Tue Aug 30 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 2.5.3-2.3.13.1
- Rebase on latest package from CH 8.3 Preview
- Re-add changes to produce openvswitch-ipsec subpackage

* Tue Jun 14 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.13
- CA-367973: Backport bond-related patches to fix XSI-1198

* Tue Mar 15 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.12
- CA-364343: Honour updelay when LACP is used

* Mon Feb 14 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.11
- CA-357261: Hide expected errors from logrotate script
- Drop unneeded BuildRequires
- CP-38416: Enable static analysis

* Fri Feb 19 2021 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.10
- CA-351960: CVE-2020-35498: Support extra padding length

* Mon May 18 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.9
- CA-339588: vswitchd: Use MCL_ONFAULT

* Tue May 12 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.8
- CP-33375: Turn off the address sanitizer

* Mon Apr 20 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.7
- CP-33305: Try and protect OVS from OOM
- Roll CP-33305-dont-kill-ovs.patch into CP-15129-Convert-to-use-systemd-services.patch
- CA-331103: Fix crash in mbundle_lookup()

* Tue Mar 24 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.6
- CA-331103: Turn on the address sanitizer temporarily

* Fri Mar 20 2020 Xin Li <xin.li@citrix.com> - 2.5.3-2.3.5
- CP-32957: remove the open vSwitch configure dialog from xsconsole

* Fri Feb 21 2020 Steven Woods <steven.woods@citrix.com> - 2.5.3-2.3.4
- CP33120: Add Coverity build macros

* Fri Jul 19 2019 Deli Zhang <deli.zhang@citrix.com> - 2.5.3-2.3.3
- CA-320193: Revert OVS from CCM rpath link

* Wed Jun 19 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.2
- CA-321784: Fix LACP bond interface flapping

* Wed May 08 2019 Jennifer Herbert <jennifer.herbert@citrix.com> - 2.5.3-2.3.1
- CA-318197: Correct logging path

* Wed Mar 27 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.5.3-2.3.0
- CA-308221: Add OVS patches required by Rackspace

* Mon Apr 23 2018 Simon Rowe <simon.rowe@citrix.com> - 2.5.3-2.2.3
- CA-288424: Fix sporadic output of incoming packets back to the same port

* Mon Apr 16 2018 Simon Rowe <simon.rowe@citrix.com> - 2.5.3-2.2.2
- CA-281351: Stop services that require network before openvswitch

* Fri Sep 22 2017 Yang Qian <yang.qian@citrix.com> - 2.5.3-2.2.1
- REQ-230 Multicast support

