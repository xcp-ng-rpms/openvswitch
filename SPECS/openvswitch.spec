# Copyright (C) 2009, 2010, 2013, 2014 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.
#
# If tests have to be skipped while building, specify the '--without check'
# option. For example:
# rpmbuild -bb --without check rhel/openvswitch-fedora.spec

# This defines the base package name's version.

%define pkgname openvswitch3.7


%if 0%{?commit:1}
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%endif

# Enable PIE, bz#955181
%global _hardened_build 1

# RHEL-7 doesn't define _rundir macro yet
# Fedora 15 onwards uses /run as _rundir
%if 0%{!?_rundir:1}
%define _rundir /run
%endif

%global rpm_supports_sysysers_m    %(rpm --version | awk -e '{print ($3 > 4.20)}')

# FIXME Test "STP - flush the fdb and mdb when topology changed" fails on s390x
# FIXME 2 tests fails on ppc64le. They will be hopefully fixed before official 2.11
%ifarch %{ix86} x86_64 aarch64
%bcond_without check
%else
%bcond_with check
%endif
# option to run kernel datapath tests, requires building as root!
%bcond_with check_datapath_kernel
# option to build with libcap-ng, needed for running OVS as regular user
%bcond_without libcapng
# option to build with ipsec support
%bcond_without ipsec

# Build python2 (that provides python) and python3 subpackages on Fedora
# Build only python3 (that provides python) subpackage on RHEL8
# Build only python subpackage on RHEL7
%if 0%{?rhel} > 7 || 0%{?fedora}
# On RHEL8 Sphinx is included in buildroot
%global external_sphinx 1
%else
# Don't use external sphinx (RHV doesn't have optional repositories enabled)
%global external_sphinx 0
%endif

Name: %{pkgname}
Summary: Open vSwitch
Group: System Environment/Daemons daemon/database/utilities
URL: http://www.openvswitch.org/
Version: 3.7.1
Release: 3%{?dist}

# Nearly all of openvswitch is ASL 2.0.  The bugtool is LGPLv2+, and the
# lib/sflow*.[ch] files are SISSL
# datapath/ is GPLv2 (although not built into any of the binary packages)
License: ASL 2.0 and LGPLv2+ and SISSL

%define dpdkver 25.11
%define dpdkdir dpdk
%define dpdksver %(echo %{dpdkver} | cut -d. -f-2)
# NOTE: DPDK does not currently build for s390x
# DPDK on aarch64 is not stable enough to be enabled in FDP
%if 0%{?rhel} > 7 || 0%{?fedora}
%define dpdkarches x86_64 ppc64le
%else
%define dpdkarches
%endif

%define ovsver 3.7.1
%define patchver 3.7
%if 0%{?commit:1}
Source: https://github.com/openvswitch/ovs/archive/%{commit}.tar.gz#/openvswitch-%{commit}.tar.gz
%else
Source: https://github.com/openvswitch/ovs/archive/v%{ovsver}.tar.gz#/openvswitch-%{ovsver}.tar.gz
%endif
Source2: openvswitch.sysusers
Source3: openvswitch-hugetlbfs.sysusers
Source10: https://fast.dpdk.org/rel/dpdk-%{dpdkver}.tar.xz

%define docutilsver 0.12
%define pygmentsver 1.4
%define sphinxver   1.2.3
%define pyelftoolsver 0.27
Source100: https://pypi.io/packages/source/d/docutils/docutils-%{docutilsver}.tar.gz
Source101: https://pypi.io/packages/source/P/Pygments/Pygments-%{pygmentsver}.tar.gz
Source102: https://pypi.io/packages/source/S/Sphinx/Sphinx-%{sphinxver}.tar.gz
Source103: https://pypi.io/packages/source/p/pyelftools/pyelftools-%{pyelftoolsver}.tar.gz

Patch0:    openvswitch-%{patchver}.patch

# The DPDK is designed to optimize througput of network traffic using, among
# other techniques, carefully crafted assembly instructions.  As such it
# needs extensive work to port it to other architectures.
ExclusiveArch: x86_64 aarch64 ppc64le s390x

# Do not enable this otherwise YUM will break on any upgrade.
# Provides: openvswitch
Conflicts: openvswitch < 3.7
Conflicts: openvswitch-dpdk < 3.7
Conflicts: openvswitch2.10
Conflicts: openvswitch2.11
Conflicts: openvswitch2.12
Conflicts: openvswitch2.13
Conflicts: openvswitch2.14
Conflicts: openvswitch2.15
Conflicts: openvswitch2.16
Conflicts: openvswitch2.17
Conflicts: openvswitch3.0
Conflicts: openvswitch3.1
Conflicts: openvswitch3.2
Conflicts: openvswitch3.3
Conflicts: openvswitch3.4
Conflicts: openvswitch3.5
Conflicts: openvswitch3.6

# FIXME Sphinx is used to generate some manpages, unfortunately, on RHEL, it's
# in the -optional repository and so we can't require it directly since RHV
# doesn't have the -optional repository enabled and so TPS fails
%if %{external_sphinx}
BuildRequires: python3-sphinx
%else
# Sphinx dependencies
BuildRequires: python-devel
BuildRequires: python-setuptools
#BuildRequires: python2-docutils
BuildRequires: python-jinja2
BuildRequires: python-nose
#BuildRequires: python2-pygments
# docutils dependencies
BuildRequires: python-imaging
# pygments dependencies
BuildRequires: python-nose
%endif

BuildRequires: gcc gcc-c++ make
BuildRequires: autoconf automake libtool
BuildRequires: systemd-units systemd-rpm-macros openssl openssl-devel
BuildRequires: python3-devel python3-setuptools
BuildRequires: desktop-file-utils
BuildRequires: groff-base graphviz
BuildRequires: unbound-devel
BuildRequires: systemtap-sdt-devel
# make check dependencies
BuildRequires: procps-ng
%if %{with check_datapath_kernel}
BuildRequires: nmap-ncat
# would be useful but not available in RHEL or EPEL
#BuildRequires: pyftpdlib
%endif

%if %{with libcapng}
BuildRequires: libcap-ng libcap-ng-devel
%endif

%ifarch %{dpdkarches}
BuildRequires: meson
%if 0%{?rhel} > 8 || 0%{?fedora}
BuildRequires: python3-pyelftools
%endif
# DPDK driver dependencies
BuildRequires: zlib-devel numactl-devel libarchive-devel
# libarchive static dependencies
BuildRequires: bzip2-devel libacl-devel libxml2-devel libzstd-devel lz4-devel xz-devel
%ifarch x86_64
BuildRequires: rdma-core-devel >= 15 libmnl-devel
%endif

# Required by packaging policy for the bundled DPDK
Provides: bundled(dpdk) = %{dpdkver}
%endif

Requires: openssl iproute module-init-tools
#Upstream kernel commit 4f647e0a3c37b8d5086214128614a136064110c3
#Requires: kernel >= 3.15.0-0
Requires: openvswitch-selinux-extra-policy

%{?sysusers_requires_compat}
%if ! %rpm_supports_sysysers_m
Requires(post): /usr/sbin/usermod
%endif
Requires(post): /bin/sed
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
Obsoletes: openvswitch-controller <= 0:2.1.0-1

%if 0%{?rhel}
# sortedcontainers are not packaged on RHEL yet, but ovs includes it
%global __requires_exclude ^python%{python3_version}dist\\(sortedcontainers\\)$
%endif

%description
Open vSwitch provides standard network bridging functions and
support for the OpenFlow protocol for remote per-flow control of
traffic.

%package -n python3-%{pkgname}
Summary: Open vSwitch python3 bindings
License: ASL 2.0
Requires: %{pkgname} = %{?epoch:%{epoch}:}%{version}-%{release}
Provides: python-%{pkgname} = %{?epoch:%{epoch}:}%{version}-%{release}

%description -n python3-%{pkgname}
Python bindings for the Open vSwitch database

%package test
Summary: Open vSwitch testing utilities
License: ASL 2.0
BuildArch: noarch
Requires: python3-%{pkgname} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires: tcpdump

%description test
Utilities that are useful to diagnose performance and connectivity
issues in Open vSwitch setup.

%package devel
Summary: Open vSwitch OpenFlow development package (library, headers)
License: ASL 2.0
Requires: %{pkgname} = %{?epoch:%{epoch}:}%{version}-%{release}

%description devel
This provides shared library, libopenswitch.so and the openvswitch header
files needed to build an external application.

%if 0%{?rhel} == 8 || 0%{?fedora} > 28
%package -n network-scripts-%{name}
Summary: Open vSwitch legacy network service support
License: ASL 2.0
Requires: network-scripts
Supplements: (%{name} and network-scripts)

%description -n network-scripts-%{name}
This provides the ifup and ifdown scripts for use with the legacy network
service.
%endif

%if %{with ipsec}
%package ipsec
Summary: Open vSwitch IPsec tunneling support
License: ASL 2.0
Requires: python3-%{pkgname} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires: libreswan

%description ipsec
This package provides IPsec tunneling support for OVS tunnels.
%endif

%prep
%if 0%{?commit:1}
%setup -q -n ovs-%{commit} -a 10
%else
%setup -q -n ovs-%{ovsver} -a 10
%endif
%if ! %{external_sphinx}
%if 0%{?commit:1}
%setup -n ovs-%{commit} -q -D -T -a 100 -a 101 -a 102
%else
%setup -n ovs-%{ovsver} -q -D -T -a 100 -a 101 -a 102
%endif
%endif
%if 0%{?rhel} && 0%{?rhel} < 9
%if 0%{?commit:1}
%setup -n ovs-%{commit} -q -D -T -a 103
%else
%setup -n ovs-%{ovsver} -q -D -T -a 103
%endif
%endif

mv dpdk-*/ %{dpdkdir}/

%if 0%{?PATCH0:1}%{!?PATCH0:0}
%patch -P0 -p1
%endif

%build
%if 0%{?rhel} && 0%{?rhel} < 9
export PYTHONPATH="${PWD}/pyelftools-%{pyelftoolsver}"
%endif
# Build Sphinx on RHEL
%if ! %{external_sphinx}
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}%{_builddir}/pytmp/lib/python"
for x in docutils-%{docutilsver} Pygments-%{pygmentsver} Sphinx-%{sphinxver}; do
    pushd "$x"
    python2 setup.py install --home %{_builddir}/pytmp
    popd
done

export PATH="$PATH:%{_builddir}/pytmp/bin"
%endif

sed -i "s/^AC_INIT(openvswitch,.*,/AC_INIT(openvswitch, %{version},/" configure.ac

./boot.sh

%ifarch %{dpdkarches}
# Lets build DPDK first
cd %{dpdkdir}

ENABLED_DRIVERS=(
    bus/pci
    bus/vdev
    mempool/ring
    net/failsafe
    net/i40e
    net/ring
    net/vhost
    net/virtio
    net/tap
)

%ifarch x86_64
ENABLED_DRIVERS+=(
    bus/auxiliary
    bus/vmbus
%if "%{dpdkver}" < "25.11"
    common/iavf
%endif
    common/mlx5
    net/bnxt
    net/enic
    net/iavf
    net/ice
    net/mlx5
    net/netvsc
    net/nfp
    net/qede
    net/vdev_netvsc
%if "%{dpdkver}" >= "23.11"
    baseband/acc
    common/nfp
%endif
)
%endif

%ifarch aarch64 x86_64
ENABLED_DRIVERS+=(
    net/e1000
    net/ixgbe
)
%endif

for driver in "${ENABLED_DRIVERS[@]}"; do
    enable_drivers="${enable_drivers:+$enable_drivers,}"$driver
done

# If doing any updates, this must be aligned with:
# https://access.redhat.com/articles/3538141
%if "%{dpdkver}" < "23.11"
DISABLED_LIBS=(
    gpudev
    kni
    jobstats
    power
)

for lib in "${DISABLED_LIBS[@]}"; do
    disable_libs="${disable_libs:+$disable_libs,}"$lib
done
%else
ENABLED_LIBS=(
    bbdev
    bitratestats
    bpf
    cmdline
    cryptodev
    dmadev
    gro
    gso
    hash
    ip_frag
    latencystats
    member
    meter
    metrics
    pcapng
    pdump
    security
    stack
    vhost
)

for lib in "${ENABLED_LIBS[@]}"; do
    enable_libs="${enable_libs:+$enable_libs,}"$lib
done
%endif

%set_build_flags
%__meson --prefix=%{_builddir}/dpdk-build \
         --buildtype=plain \
%if "%{dpdkver}" < "23.11"
         -Ddisable_libs="$disable_libs" \
%else
         -Denable_libs="$enable_libs" \
%endif
         -Ddisable_apps="*" \
         -Denable_drivers="$enable_drivers" \
         -Dplatform=generic \
         -Dmax_ethports=1024 \
         -Dmax_numa_nodes=8 \
         -Dtests=false \
         %{_vpath_builddir}

# Check drivers and libraries
for driver in "${ENABLED_DRIVERS[@]}"; do
        config_token="RTE_$(echo "$driver" | tr [a-z/] [A-Z_])"
        ! grep -Fqw "$config_token" */rte_build_config.h || continue
        echo "!!! Could not find $driver in rte_build_config.h, please check dependencies. !!!"
        false
done
for lib in "${ENABLED_LIBS[@]}"; do
        config_token="RTE_LIB_$(echo "$lib" | tr [a-z/] [A-Z_])"
        ! grep -Fqw "$config_token" */rte_build_config.h || continue
        echo "!!! Could not find $lib in rte_build_config.h, please check dependencies. !!!"
        false
done
%meson_build
%__meson install -C %{_vpath_builddir} --no-rebuild

# FIXME currently with LTO enabled OVS tries to link with both static and shared libraries
rm -v %{_builddir}/dpdk-build/%{_lib}/*.so*

# Generate a list of supported drivers, its hard to tell otherwise.
cat << EOF > README.DPDK-PMDS
DPDK drivers included in this package:

EOF

for f in %{_builddir}/dpdk-build/%{_lib}/librte_net_*.a; do
    basename ${f} | cut -c12- | cut -d. -f1 | tr [:lower:] [:upper:]
done >> README.DPDK-PMDS

cat << EOF >> README.DPDK-PMDS

For further information about the drivers, see
http://dpdk.org/doc/guides-%{dpdksver}/nics/index.html
EOF

cd -
%endif

# And now for OVS...
mkdir build-shared build-static
pushd build-shared
ln -s ../configure
%configure \
%if %{with libcapng}
        --enable-libcapng \
%else
        --disable-libcapng \
%endif
        --disable-static \
        --enable-shared \
        --enable-ssl \
        --with-pkidir=%{_sharedstatedir}/openvswitch/pki \
        --enable-usdt-probes \
        --disable-afxdp \
        --with-version-suffix=-%{release}
make %{?_smp_mflags}
popd
pushd build-static
ln -s ../configure
%ifarch %{dpdkarches}
PKG_CONFIG_PATH=%{_builddir}/dpdk-build/%{_lib}/pkgconfig \
%endif
%configure \
%if %{with libcapng}
        --enable-libcapng \
%else
        --disable-libcapng \
%endif
        --enable-ssl \
%ifarch %{dpdkarches}
        --with-dpdk=static \
%endif
        --with-pkidir=%{_sharedstatedir}/openvswitch/pki \
        --enable-usdt-probes \
        --disable-afxdp \
        --with-version-suffix=-%{release}
make %{?_smp_mflags}
popd

/usr/bin/python3 build-aux/dpdkstrip.py \
        --dpdk \
        < rhel/usr_lib_systemd_system_ovs-vswitchd.service.in \
        > rhel/usr_lib_systemd_system_ovs-vswitchd.service

%install
rm -rf $RPM_BUILD_ROOT
make -C build-shared install sbin_PROGRAMS=ovsdb/ovsdb-server DESTDIR=$RPM_BUILD_ROOT
make -C build-static install bin_PROGRAMS= sbin_PROGRAMS=vswitchd/ovs-vswitchd DESTDIR=$RPM_BUILD_ROOT

install -d -m 0755 $RPM_BUILD_ROOT%{_rundir}/openvswitch
install -d -m 0750 $RPM_BUILD_ROOT%{_localstatedir}/log/openvswitch
install -d -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/openvswitch

install -p -D -m 0644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysusersdir}/openvswitch.conf
%ifarch %{dpdkarches}
install -p -D -m 0644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysusersdir}/openvswitch-hugetlbfs.conf
%endif

install -p -D -m 0644 rhel/usr_lib_udev_rules.d_91-vfio.rules \
        $RPM_BUILD_ROOT%{_udevrulesdir}/91-vfio.rules

install -p -D -m 0644 \
        rhel/usr_share_openvswitch_scripts_systemd_sysconfig.template \
        $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/openvswitch

for service in openvswitch ovsdb-server ovs-vswitchd \
               ovs-delete-transient-ports; do
        install -p -D -m 0644 \
                        rhel/usr_lib_systemd_system_${service}.service \
                        $RPM_BUILD_ROOT%{_unitdir}/${service}.service
done

%if %{with ipsec}
install -p -D -m 0644 rhel/usr_lib_systemd_system_openvswitch-ipsec.service \
                      $RPM_BUILD_ROOT%{_unitdir}/openvswitch-ipsec.service
%endif

install -m 0755 rhel/etc_init.d_openvswitch \
        $RPM_BUILD_ROOT%{_datadir}/openvswitch/scripts/openvswitch.init

install -p -D -m 0644 rhel/etc_openvswitch_default.conf \
        $RPM_BUILD_ROOT/%{_sysconfdir}/openvswitch/default.conf

install -p -D -m 0644 rhel/etc_logrotate.d_openvswitch \
        $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/openvswitch

install -m 0644 vswitchd/vswitch.ovsschema \
        $RPM_BUILD_ROOT/%{_datadir}/openvswitch/vswitch.ovsschema

%if 0%{?rhel} < 9
install -d -m 0755 $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/network-scripts/
install -p -m 0755 rhel/etc_sysconfig_network-scripts_ifdown-ovs \
        $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/network-scripts/ifdown-ovs
install -p -m 0755 rhel/etc_sysconfig_network-scripts_ifup-ovs \
        $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/network-scripts/ifup-ovs
%endif

install -d -m 0755 $RPM_BUILD_ROOT%{python3_sitelib}
cp -a $RPM_BUILD_ROOT/%{_datadir}/openvswitch/python/ovstest \
        $RPM_BUILD_ROOT%{python3_sitelib}

# Build the JSON C extension for the Python lib (#1417738)
pushd python
(
export CPPFLAGS="-I ../include -I ../build-shared/include"
export LDFLAGS="%{__global_ldflags} -L $RPM_BUILD_ROOT%{_libdir}"
%py3_build
%py3_install
[ -f "$RPM_BUILD_ROOT/%{python3_sitearch}/ovs/_json$(python3-config --extension-suffix)" ]
)
popd

rm -rf $RPM_BUILD_ROOT/%{_datadir}/openvswitch/python/

install -d -m 0755 $RPM_BUILD_ROOT/%{_sharedstatedir}/openvswitch

install -d -m 0755 $RPM_BUILD_ROOT%{_prefix}/lib/firewalld/services/

install -p -D -m 0755 \
        rhel/usr_share_openvswitch_scripts_ovs-systemd-reload \
        $RPM_BUILD_ROOT%{_datadir}/openvswitch/scripts/ovs-systemd-reload

touch $RPM_BUILD_ROOT%{_sysconfdir}/openvswitch/conf.db
# The db needs special permission as IPsec Pre-shared keys are stored in it.
chmod 0640 $RPM_BUILD_ROOT%{_sysconfdir}/openvswitch/conf.db

touch $RPM_BUILD_ROOT%{_sysconfdir}/openvswitch/system-id.conf

# remove unpackaged files
rm -f $RPM_BUILD_ROOT/%{_bindir}/ovs-benchmark \
        $RPM_BUILD_ROOT/%{_bindir}/ovs-docker \
        $RPM_BUILD_ROOT/%{_bindir}/ovs-parse-backtrace \
        $RPM_BUILD_ROOT/%{_bindir}/ovs-testcontroller \
        $RPM_BUILD_ROOT/%{_sbindir}/ovs-vlan-bug-workaround \
        $RPM_BUILD_ROOT/%{_mandir}/man1/ovs-benchmark.1* \
        $RPM_BUILD_ROOT/%{_mandir}/man8/ovs-testcontroller.* \
        $RPM_BUILD_ROOT/%{_mandir}/man8/ovs-vlan-bug-workaround.8*

%if ! %{with ipsec}
rm -f $RPM_BUILD_ROOT/%{_datadir}/openvswitch/scripts/ovs-monitor-ipsec
%endif

# remove ovn unpackages files
rm -f $RPM_BUILD_ROOT%{_bindir}/ovn*
rm -f $RPM_BUILD_ROOT%{_mandir}/man1/ovn*
rm -f $RPM_BUILD_ROOT%{_mandir}/man5/ovn*
rm -f $RPM_BUILD_ROOT%{_mandir}/man7/ovn*
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/ovn*
rm -f $RPM_BUILD_ROOT%{_datadir}/openvswitch/ovn*
rm -f $RPM_BUILD_ROOT%{_datadir}/openvswitch/scripts/ovn*
rm -f $RPM_BUILD_ROOT%{_includedir}/ovn/*

%check
%if %{with check}
    pushd build-static
    touch resolv.conf
    export OVS_RESOLV_CONF=$(pwd)/resolv.conf
    if make check TESTSUITEFLAGS='%{_smp_mflags}' ||
       make check TESTSUITEFLAGS='--recheck'; then :;
    else
        cat tests/testsuite.log
        exit 1
    fi
    popd
%endif
%if %{with check_datapath_kernel}
    pushd build-static
    if make check-kernel RECHECK=yes; then :;
    else
        cat tests/system-kmod-testsuite.log
        exit 1
    fi
    popd
%endif

%preun
%if 0%{?systemd_preun:1}
    %systemd_preun openvswitch.service
%else
    if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
        /bin/systemctl --no-reload disable openvswitch.service >/dev/null 2>&1 || :
        /bin/systemctl stop openvswitch.service >/dev/null 2>&1 || :
    fi
%endif

%pre
%sysusers_create_compat %{SOURCE2}
%ifarch %{dpdkarches}
%sysusers_create_compat %{SOURCE3}
%if ! %rpm_supports_sysysers_m
usermod -a -G hugetlbfs openvswitch
%endif
%endif

%post
if [ $1 -eq 1 ]; then
    sed -i 's:^#OVS_USER_ID=:OVS_USER_ID=:' /etc/sysconfig/openvswitch

%ifarch %{dpdkarches}
    sed -i \
        's@OVS_USER_ID="openvswitch:openvswitch"@OVS_USER_ID="openvswitch:hugetlbfs"@'\
        /etc/sysconfig/openvswitch
%endif
fi
chown -R openvswitch:openvswitch /etc/openvswitch

%if 0%{?systemd_post:1}
    %systemd_post openvswitch.service
%else
    # Package install, not upgrade
    if [ $1 -eq 1 ]; then
        /bin/systemctl daemon-reload >/dev/null || :
    fi
%endif

%postun
%if 0%{?systemd_postun:1}
    %systemd_postun openvswitch.service
%else
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

%triggerun -- openvswitch < 2.5.0-22.git20160727%{?dist}
# old rpm versions restart the service in postun, but
# due to systemd some preparation is needed.
if systemctl is-active openvswitch >/dev/null 2>&1 ; then
    /usr/share/openvswitch/scripts/ovs-ctl stop >/dev/null 2>&1 || :
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl stop openvswitch ovsdb-server ovs-vswitchd >/dev/null 2>&1 || :
    systemctl start openvswitch >/dev/null 2>&1 || :
fi
exit 0

%files -n python3-%{pkgname}
%{python3_sitearch}/ovs
%{python3_sitearch}/ovs-*.egg-info
%if "%{version}" >= "3.5.0"
%{_bindir}/ovs-flowviz
%{_mandir}/man8/ovs-flowviz.8*
%endif
%doc LICENSE

%files test
%{_bindir}/ovs-pcap
%{_bindir}/ovs-tcpdump
%{_bindir}/ovs-tcpundump
%{_datadir}/openvswitch/scripts/usdt/*
%{_mandir}/man1/ovs-pcap.1*
%{_mandir}/man8/ovs-tcpdump.8*
%{_mandir}/man1/ovs-tcpundump.1*
%{_bindir}/ovs-test
%{_bindir}/ovs-vlan-test
%{_bindir}/ovs-l3ping
%{_mandir}/man8/ovs-test.8*
%{_mandir}/man8/ovs-vlan-test.8*
%{_mandir}/man8/ovs-l3ping.8*
%{python3_sitelib}/ovstest

%files devel
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/openvswitch/*
%{_includedir}/openflow/*
%exclude %{_libdir}/*.a
%exclude %{_libdir}/*.la

%if 0%{?rhel} == 8 || 0%{?fedora} > 28
%files -n network-scripts-%{name}
%{_sysconfdir}/sysconfig/network-scripts/ifup-ovs
%{_sysconfdir}/sysconfig/network-scripts/ifdown-ovs
%endif

%files
%defattr(-,openvswitch,openvswitch)
%dir %{_sysconfdir}/openvswitch
%{_sysconfdir}/openvswitch/default.conf
%config %ghost %verify(not owner group md5 size mtime) %{_sysconfdir}/openvswitch/conf.db
%ghost %attr(0600,-,-) %verify(not owner group md5 size mtime) %{_sysconfdir}/openvswitch/.conf.db.~lock~
%config %ghost %{_sysconfdir}/openvswitch/system-id.conf
%defattr(-,root,root)
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/sysconfig/openvswitch
%{_sysconfdir}/bash_completion.d/ovs-appctl-bashcomp.bash
%{_sysconfdir}/bash_completion.d/ovs-vsctl-bashcomp.bash
%config(noreplace) %{_sysconfdir}/logrotate.d/openvswitch
%{_unitdir}/openvswitch.service
%{_unitdir}/ovsdb-server.service
%{_unitdir}/ovs-vswitchd.service
%{_unitdir}/ovs-delete-transient-ports.service
%{_datadir}/openvswitch/scripts/openvswitch.init
%{_datadir}/openvswitch/scripts/ovs-check-dead-ifs
%{_datadir}/openvswitch/scripts/ovs-lib
%{_datadir}/openvswitch/scripts/ovs-save
%{_datadir}/openvswitch/scripts/ovs-vtep
%{_datadir}/openvswitch/scripts/ovs-ctl
%{_datadir}/openvswitch/scripts/ovs-kmod-ctl
%{_datadir}/openvswitch/scripts/ovs-systemd-reload
%config %{_datadir}/openvswitch/local-config.ovsschema
%config %{_datadir}/openvswitch/vswitch.ovsschema
%config %{_datadir}/openvswitch/vtep.ovsschema
%{_bindir}/ovs-appctl
%{_bindir}/ovs-dpctl
%{_bindir}/ovs-ofctl
%{_bindir}/ovs-vsctl
%{_bindir}/ovsdb-client
%{_bindir}/ovsdb-tool
%{_bindir}/ovs-pki
%{_bindir}/vtep-ctl
%{_libdir}/*.so.*
%{_sbindir}/ovs-vswitchd
%{_sbindir}/ovsdb-server
%{_mandir}/man1/ovsdb-client.1*
%{_mandir}/man1/ovsdb-server.1*
%{_mandir}/man1/ovsdb-tool.1*
%{_mandir}/man5/ovsdb.5*
%{_mandir}/man5/ovsdb.local-config.5*
%{_mandir}/man5/ovsdb-server.5.*
%{_mandir}/man5/ovs-vswitchd.conf.db.5*
%{_mandir}/man5/vtep.5*
%{_mandir}/man7/ovsdb-server.7*
%{_mandir}/man7/ovsdb.7*
%{_mandir}/man7/ovs-actions.7*
%{_mandir}/man7/ovs-fields.7*
%{_mandir}/man8/vtep-ctl.8*
%{_mandir}/man8/ovs-appctl.8*
%{_mandir}/man8/ovs-ctl.8*
%{_mandir}/man8/ovs-dpctl.8*
%{_mandir}/man8/ovs-kmod-ctl.8.*
%{_mandir}/man8/ovs-ofctl.8*
%{_mandir}/man8/ovs-pki.8*
%{_mandir}/man8/ovs-vsctl.8*
%{_mandir}/man8/ovs-vswitchd.8*
%{_mandir}/man8/ovs-parse-backtrace.8*
%{_udevrulesdir}/91-vfio.rules
%doc LICENSE NOTICE README.rst NEWS rhel/README.RHEL.rst
%ifarch %{dpdkarches}
%doc %{dpdkdir}/README.DPDK-PMDS
%attr(750,openvswitch,hugetlbfs) %verify(not owner group) /var/log/openvswitch
%else
%attr(750,openvswitch,openvswitch) %verify(not owner group) /var/log/openvswitch
%endif
/var/lib/openvswitch
%ghost %attr(755,root,root) %verify(not owner group) %{_rundir}/openvswitch
%{_datadir}/openvswitch/bugtool-plugins/
%{_datadir}/openvswitch/scripts/ovs-bugtool-*
%{_bindir}/ovs-dpctl-top
%{_sbindir}/ovs-bugtool
%{_mandir}/man8/ovs-dpctl-top.8*
%{_mandir}/man8/ovs-bugtool.8*
%if (0%{?rhel} && 0%{?rhel} <= 7) || (0%{?fedora} && 0%{?fedora} < 29)
%{_sysconfdir}/sysconfig/network-scripts/ifup-ovs
%{_sysconfdir}/sysconfig/network-scripts/ifdown-ovs
%endif
%{_sysusersdir}/openvswitch.conf
%ifarch %{dpdkarches}
%{_sysusersdir}/openvswitch-hugetlbfs.conf
%endif

%if %{with ipsec}
%files ipsec
%{_datadir}/openvswitch/scripts/ovs-monitor-ipsec
%{_unitdir}/openvswitch-ipsec.service
%endif

%changelog
* Tue Apr 14 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.1-3
- Merging upstream branch-3.7 [RH git: 792308e643]
    Commit list:
    b53965f1a1 netdev-dpdk: Fix memory leak when configuring rx-steering.


* Sun Apr 12 2026 Flavio Leitner <fbl@redhat.com> - 3.7.1-2
- Merging a916e015a6 pkgtool: refactor to modular, tested, fully.. [RH git: da884592b6]
    Commit list:
    a916e015a6 pkgtool: refactor to modular, tested, fully automated system (v2)


* Tue Apr 07 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.1-1
- Merging upstream branch-3.7 [RH git: abea941493]
    Commit list:
    1c9b2cefda stream-ssl: Disable TLS session tickets.
    78aa10ca31 Prepare for 3.7.2.
    7921d9c692 Set release date for 3.7.1.


* Tue Mar 31 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-9
- Merging upstream branch-3.7 [RH git: 0fe7181cf4]
    Commit list:
    e1b82e9b7c github: Temporarily disable system tests for DPDK and AF_XDP.
    a9785c7e1d conntrack: Fix replace_substring to handle larger packets.
    7dc6fb7baa faq: Update DPDK version for older releases to 23.11.6 and 24.11.4.


* Fri Mar 13 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-8
- Merging upstream branch-3.7 [RH git: e8ff5fb3a9]
    Commit list:
    0d4c78e153 github: Update all the actions to prepare for Node.js 24.


* Wed Mar 11 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-7
- Merging redhat subtree [RH git: 580891d4cc]
    Commit list:
    41662c2205 redhat: fix misc bugs found during security review
    ffc5dd582d redhat: update README.rst and README.dpdk
    0e5fa41626 pkgtool: fix changelog history and release numbering for point releases


* Fri Mar 06 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-6
- Merging upstream branch-3.7 [RH git: f6b7f613f9]
    Commit list:
    c052c469b0 dpctl: Fix memory leak in ipf-get-status command.


* Fri Mar 06 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-5
- Merging upstream branch-3.7 [RH git: 1e199a141b]
    Commit list:
    f86caea060 netdev-dpdk: Fix vhost_driver_flags data race in destruct.
    71dae047db coverage: Fix data race when reading idx_count in coverage_read().
    b5f36a6d61 packets: Validate ND option length in packet_set_nd().
    920eb244e9 ovs-router: Fix locking in ovs_router_rule_add().
    dd4d9983a1 ovs-router: Fix --disable-system-route rules filter.
    cd7b495e2d tests: Make routing rules checks more resilient.
    a51e475062 github: Fix potential 32-bit package installations.


* Thu Feb 26 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-4
- Merging redhat subtree [RH git: f9a2da7090]
    Commit list:
    8fac66e3f7 pkgtool: fix changelog release mismatch for point releases


* Thu Feb 19 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-3
- Merging upstream branch-3.7 [RH git: c30a493c54]
    Commit list:
    a7cd823a12 python: Fix discarded const qualifier in json_to_python.
    00b013a643 ovsdb: raft: Don't grant a pre-vote to a server that is behind. ()
    95473a95e4 ovsdb-cluster.at: Test disruptive server with outdated log and term.
    f559623f99 netdev-linux: Fix IFLA_IF_NETNSID value.


* Tue Feb 17 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-2
- Merging upstream branch-3.7 [RH git: 79b4abccba]
    Commit list:
    0a88fdec23 Revert "python: Replace deprecated License with License-Expression (PEP 639).".


* Mon Feb 16 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-1
- Merging upstream branch-3.7 [RH git: e18b331f62]
    Commit list:
    028e6268c3 Prepare for 3.7.1.
    bdb95cc192 Set release date for 3.7.0.


* Thu Feb 12 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.13
- Merging upstream branch-3.7 [RH git: 9e8a1d361c]
    Commit list:
    c1eef6db4f ovs-router: Don't report internal route priority in json output. ()


* Tue Feb 10 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.12
- Merging upstream branch-3.7 [RH git: ddf2f84483]
    Commit list:
    8c6ebf895f bond: Fix next_rebalance offset calculation.
    f43bde3d50 rhel: Avoid warning about missing .la with Fedora spec.
    37e41460eb rhel: Remove kernel mentions from the Fedora spec.
    a47cf0e6b0 rhel: Don't ship network scripts on RHEL 9+ and Fedora 41+.
    88f3274933 rhel: Don't build network scripts package on RHEL 9+ with Fedora spec.


* Tue Feb 10 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.11
- Merging upstream branch-3.7 [RH git: 8c90b4ee54]
    Commit list:
    1d57509ef1 treewide: Fix discarded-qualifers warnings.
    431efcdfcc ovsdb-server: Fix relay remotes string check.


* Mon Feb 09 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.10
- Merging upstream branch-3.7 [RH git: 38ad6006ec]
    Commit list:
    6d682ae53f dpif-offload: Move port manager into struct dpif_offload.


* Sat Feb 07 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.9
- Merging upstream branch-3.7 [RH git: dfb465b958]
    Commit list:
    d56120f431 ofproto-dpif-xlate: Avoid mirroring on recirculation.


* Fri Feb 06 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.8
- Merging upstream branch-3.7 [RH git: c67d84ba95]
    Commit list:
    1d6a519172 cirrus: Use FreeBSD release images instead of stable snapshots.
    97b3a35077 automake: Don't install the libopenvswitchavx512.


* Fri Feb 06 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.7
- Merging upstream branch-3.7 [RH git: 969c34df6e]
    Commit list:
    fcf733472c dpif-netdev: Fix per-datapath initialization using once framework.
    52e740da78 dpif: Always call dpif_offload_set_config().
    dbfe60a322 fedora: Fix package install on Fedora 43.
    0062d99d46 ipsec: libreswan: Consider active only when child SA is established. ()
    122e79a497 ipsec: libreswan: Silence warning about overriding auto=route in v5.3.
    f3d704541b ipsec: libreswan: Fix warning for obsolete keyingtries in v5.
    59c56bcf6e system-ipsec.at: Use natural sorting for SA list.


* Mon Feb 02 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.6
- Merging upstream branch-3.7 [RH git: 90a8d3bae8]
    Commit list:
    75ba627dc7 dpif-offload: Take a reference when dumping a collection.


* Mon Jan 26 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.5
- Merging upstream branch-3.7 [RH git: 053677fc3f]
    Commit list:
    a56bfa103b rconn: Fix fd leak when close monitor.


* Mon Jan 26 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.4
- Merging upstream branch-3.7 [RH git: a3daa0c2f9]
    Commit list:
    b672ea19d8 dpif-offload: Move provider priority to interface level.
    e7d7d33f4c ovs-router: Fix JSON type for user in rules/show.


* Thu Jan 22 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.3
- Merging upstream branch-3.7 [RH git: a0c25e5725]
    Commit list:
    b63ec0e359 dpdk: Avoid maybe uninitialized for found_value variable.


* Wed Jan 21 2026 Open vSwitch CI <ovs-ci@redhat.com> - 3.7.0-0.2
- Merging upstream branch-3.7 [RH git: 6a4cd68ef0]
    Commit list:
    5057e33f9c dpif-offload: Rename offload provider local functions and structures.


* Sat Jan 17 2026 Michael Santana <msantana@redhat.com> - 3.7.0-0.1
- Add 'redhat/' from commit '17b0ae25fc4c26baf0208bc676349e4c3b2bf7be' [RH git: 40425d1fba]
    git-subtree-dir: redhat
    git-subtree-mainline: e517a4914f6108c78489d08f591363b6b4628b4d
    git-subtree-split: 17b0ae25fc4c26baf0208bc676349e4c3b2bf7be


