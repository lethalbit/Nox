# Nox Attribution Guidelines

The following document describes the process and guidelines that Nox uses to attribute changes committed to the project.

## Authorship

With Nox, the Git history serves to be the record of authorship, as such with your commits the Git `Author` field should reflect the primary author of a change set.

As such, if you commit a change authored by another individual, ensure they are listed as the author, and if you commit changes authored by multiple people, then add one or more `Co-Developed-By: Jane Doe <j.doe@domain.tld>` for each co-author for the change set.

Release packages of Nox will have an automatically generated authorship file which lists all contributors.

## Certification of Origin

When contributing code to Nox, it is important that we can certify the origin of the contribution. Therefore all contributors are required to accept the [Developer's Certificate Of Origin 1.1](https://developercertificate.org/) as listed below:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To certify this, the following line should be added to the end of the Commit message: `Signed-off-by: Jane Doe <j.doe@domain.tld>`/

This can also be done by using `-s` when running `git commit`.

## Names

Your legal / real name is not required for authorship or sign-offs, as some people are uncomfortable with this.
