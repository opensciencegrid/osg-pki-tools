# This .html version of the man page should be used for web
# documentation via http://htmlpreview.github.io.
# Run make after updating osg-incommon-cert-request.1 and pushed the
# .html file into git.
man/osgincommoncertrequest.html: man/osg-incommon-cert-request.1
	groff -mandoc -Thtml man/osg-incommon-cert-request.1 > man/osgincommoncertrequest.html
