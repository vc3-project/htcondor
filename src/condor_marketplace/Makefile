#
# Upload the functions and templates to the appropriate place(s) on S3.
#

VERSION = 1
FUNCTIONS = lease-$(VERSION).zip
S3TARGETS = $(FUNCTIONS:%=.upload/%)

all : s3upload

s3upload : .upload $(S3TARGETS)

.upload :
	mkdir .upload

# Strictly speaking, only the functions needs to be in a region-specific
# bucket, but it's much easier to just upload everything everywhere.
$(S3TARGETS) : .upload/% : %
	@aws s3 cp $< s3://condor-marketplace/$(notdir $<)
	@aws s3 cp $< s3://condor-marketplace-us-east-1/$(notdir $<)
	@aws s3 cp $< s3://condor-marketplace-us-west-1/$(notdir $<)
	@aws s3 cp $< s3://condor-marketplace-us-west-2/$(notdir $<)
	@mkdir -p $(dir $@)
	@touch $@


#
# Build the function uploads from their sources.
#

lease-$(VERSION).zip : lease.js response.js moment.js
	@rm -f $@
	@zip $@ $^
