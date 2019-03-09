Summary: osg-pki-tools
Name: osg-pki-tools
Version: 3.1.0
Release: 1.1%{?dist}
Source: osg-pki-tools-%{version}.tar.gz
License: Apache 2.0
Group: Grid
URL: http://github.com/opensciencegrid/osg-pki-tools
BuildArch: noarch
Requires: python
Requires: m2crypto
BuildRequires: m2crypto
%if 0%{?rhel} < 7
Requires: python-argparse
%endif

%description
%{summary}

%prep
%setup -q

%build

%install
%{__python} setup.py install --root=%{buildroot}
rm -f %{buildroot}%{python_sitelib}/*.egg-info

%files
%dir %{python_sitelib}/osgpkitools
%{python_sitelib}/osgpkitools
%exclude %{python_sitelib}/osgpkitools/*.pyo
%{_bindir}/osg-cert-request
%{_bindir}/osg-incommon-cert-request


%changelog
* Fri Mar  8 2019 Dave Dykstra <dwd@fnal.gov> - 3.1.1-1
- Add BuildRequires: m2crypto

* Fri Mar  8 2019 Dave Dykstra <dwd@fnal.gov> - 3.1.0-1
- Add osg-incommon-cert-request

* Mon Feb 18 2019 Brian Lin <blin@cs.wisc.edu> - 3.0.1-1
- Fixed bug where osg-cert-request did not accept multi-word state/province names (SOFTWARE-3591)

* Wed Jun 27 2018 Brian Lin <blin@cs.wisc.edu> - 3.0.0-1
- Remove tools and libraries designed for use with OIM
- Add an option to request CSRs (SOFTWARE-3228)

* Tue Jan 23 2018 Brian Lin <blin@cs.wisc.edu> - 2.1.4-1
- Fix errors that prevented osg-user-cert-renew and osg-cert-revoke from running

* Fri Jan 12 2018 Brian Lin <blin@cs.wisc.edu> - 2.1.3-1
- Fix osg-user-cert-renew when called without cert and key options (SOFTWARE-3061)

* Fri Dec 08 2017 Brian Lin <blin@cs.wisc.edu> - 2.1.2-1
- Fix bug that prevented requesting service certificates (SOFTWARE-3051)
- Handle HTTPS failed responses when the HTTPS connection succeeds and
  the HTTP connection fails (SOFTWARE-3034)

* Thu Dec 07 2017 Brian Lin <blin@cs.wisc.edu> - 2.1.1-1
- Catch exceptions when network unreachable (SOFTWARE-3047)
- Handle unreachable network in HTTP fallback logic (SOFTWARE-3034)

* Tue Nov 28 2017 Brian Lin <blin@cs.wisc.edu> - 2.1.0-1
- Attempt HTTPS connections before falling back to HTTP (SOFTWARE-3034)
- Restore original key names if writing new keys fails (SOFTWARE-3000)
- Fixup osg-cert-request help message (SOFTWARE-3001)
- Replace goc@opensciencegrid.org with updated address (SOFTWARE-3013)

* Tue Oct 31 2017 Brian Lin <blin@cs.wisc.edu> - 2.0.0-1
- osg-cert-request defaults to authenticated requests (SOFTWARE-2898)
- Certificate request quota verification is now performed server-side (SOFTWARE-2472)
- Remove 'tests' package since the tests are not ready for public consumption

* Mon Oct 24 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.20-1
- Generate SHA2 CSRs (SOFTWARE-2136)

* Mon Aug 22 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.19-1
- Fix formatting of CSRs (SOFTWARE-2132)
- Reword 'bad VO info' error from osg-*cert-request (SOFTWARE-2405)

* Wed May 25 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.18-1
- Added timeout to osg-user-cert-revoke (SOFTWARE-2322)

* Wed May 04 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.17-1
- Fix missing import in osg-user-cert-renew

* Mon Apr 25 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.16-1
- Fix timeout option to respect tool runtime (SOFTWARE-2258)
- Improve PKI tool error message when missing VO request information (SOFTWARE-2292)

* Thu Mar 24 2016 Brian Lin <blin@cs.wisc.edu> - 1.2.15-1
- Added --csr and --hostname options conflict to osg-cert-request

* Thu Dec 17 2015 Brian Lin <blin@cs.wisc.edu> - 1.2.14-1
- Accept hostname aliases in cert requests (SOFTWARE-2114)
- Refactor tests (SOFTWARE-2120)

* Thu Dec 10 2015 Brian Lin <blin@cs.wisc.edu> - 1.2.13-1
- Certificate requests fail without setting the CSR version (SOFTWARE-1936)

* Tue Mar 31 2015 Brian Lin <blin@cs.wisc.edu> - 1.2.12-1
- Fix to osg-user-cert-renew using old SSL protocols
- Check write permissions of output dir before renewing certs

* Fri Oct 24 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.11-1
- Fix to avoid SSLv3 due to the POODLE vulnerability

* Tue Aug 19 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.10-1
- Catch uncaught exceptions when missing request VO (SOFTWARE-1584)

* Mon Aug 18 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.9-1
- Add ability to revoke specific certs by serial ID (SOFTWARE-1494)

* Tue Jun 17 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.8-1
- Change required options in retrieve/revoke tools to be required args (SOFTWARE-1500)
- Fix redundant input param when providing CSR (SOFTWARE-1502)

* Wed Mar 05 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.7-1
- Fix osg-user-cert-renew error on EL5

* Tue Feb 25 2014 Brian Lin <blin@cs.wisc.edu> - 1.2.6-1
- Pull PKCS12 files from OIM (SOFTWARE-1229)
- Add ability to add CC's to the GOC ticket when requesting certs (SOFTWARE-1318)
- Fix VO option when requesting a new cert (SOFTWARE-1386)

* Thu Nov 21 2013 Brian Lin <blin@cs.wisc.edu> - 1.2.5-1
- Handle blank lines in hostfile for osg-gridadmin-cert-request (SOFTWARE-1271)
- Fix bugs in exception handling (SOFTWARE-1201)

* Thu Nov 07 2013 Brian Lin <blin@cs.wisc.edu> - 1.2.4-1
- Handle all IO errors

* Mon Oct 28 2013 Brian Lin <blin@cs.wisc.edu> - 1.2.3-1
- Handle no such file/directory errors explicitly

* Thu Oct 17 2013 Brian Lin <blin@cs.wisc.edu> - 1.2.2-1
- Improve exception handling when typos occur on the command-line (SOFTWARE-1183)

* Mon Jul 08 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.2.1-4
- Add documentation

* Mon Jul 08 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.2.1-3
- Bump to rebuild

* Thu Jun 27 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.2.1-2
- Bump to rebuild with fixed source

* Tue Jun 25 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.2.1-1
- New version 1.2.1

* Thu Jun 13 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.2.0-3
- New version 1.2
- Fix ConnectAPI imports in osg-cert-request and osg-cert-retrieve
- Fix exception handling

* Thu Mar 28 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.1.0-3
- Rebuild with fix to scripts to look for pki-clients.ini in /etc/osg

* Wed Mar 27 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.1.0-2
- Make source tarball from 1.1 tag
- Remove upstreamed patches

* Wed Feb 06 2013 Matyas Selmeci <matyas@cs.wisc.edu> - 1.1.0-1
- Version update
- Add python-ssl dependency on el5
- Fix sitelib
- Fix imports

* Thu Oct 04 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0.3-1
- Version update

* Fri Sep 28 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0.2-1
- Version update

* Thu Sep 27 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0.1-1
- Version update
- Add python-simplejson dependency
- Move unit tests
- Rename and move OSGPKIClients.ini
- Remove python-argparse dependency for tests

* Tue Sep 25 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0-4
- Add m2crypto dependency
- Add OSGPKIClients.ini

* Mon Sep 24 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0-3
- Use correct sources
- Remove patches, since they're upstream

* Fri Sep 14 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0-2
- Fix imports
- Fix os.system calls
- Catch SystemExit

* Thu Sep 13 2012 Matyas Selmeci <matyas@cs.wisc.edu> - 1.0-1
- Initial packaging
