Name:           mcr
Version:        0.1.0
Release:        1%{?dist}
Summary:        High-performance multicast relay daemon

License:        Apache-2.0 OR MIT
URL:            https://github.com/acooks/mcr
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires(pre):  shadow-utils

%description
MCR is a high-performance multicast packet relay that uses io_uring and
AF_PACKET for zero-copy packet forwarding between network interfaces.

%prep
%autosetup

%build
cargo build --release

%install
# Binaries
install -Dm755 target/release/mcrd %{buildroot}%{_bindir}/mcrd
install -Dm755 target/release/mcrctl %{buildroot}%{_bindir}/mcrctl
install -Dm755 target/release/mcrgen %{buildroot}%{_bindir}/mcrgen

# Systemd
install -Dm644 packaging/systemd/mcrd.service %{buildroot}%{_unitdir}/mcrd.service
install -Dm644 packaging/systemd/mcrd.sysusers %{buildroot}%{_sysusersdir}/mcrd.conf
install -Dm644 packaging/systemd/mcrd.tmpfiles %{buildroot}%{_tmpfilesdir}/mcrd.conf

# Config directory
install -dm755 %{buildroot}%{_sysconfdir}/mcr
install -Dm644 examples/config.json5 %{buildroot}%{_sysconfdir}/mcr/rules.json5.example

%pre
%sysusers_create_compat packaging/systemd/mcrd.sysusers

%post
%systemd_post mcrd.service

%preun
%systemd_preun mcrd.service

%postun
%systemd_postun_with_restart mcrd.service

%files
%license LICENSE-APACHE LICENSE-MIT
%doc README.md
%{_bindir}/mcrd
%{_bindir}/mcrctl
%{_bindir}/mcrgen
%{_unitdir}/mcrd.service
%{_sysusersdir}/mcrd.conf
%{_tmpfilesdir}/mcrd.conf
%dir %{_sysconfdir}/mcr
%config(noreplace) %{_sysconfdir}/mcr/rules.json5.example

%changelog
* Thu Dec 05 2024 MCR Team <mcr@example.com> - 0.1.0-1
- Initial package
