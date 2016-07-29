if( EXPAT_FOUND AND HAVE_EXT_OPENSSL AND HAVE_EXT_CURL )

	file( GLOB librarySources condor-aws.h condor-aws.cpp )
	condor_shared_lib( condor-aws
		"${librarySources}" )

	file( GLOB executableSources annex-poll.cpp )
	condor_exe( condor-annex-poll
		"${executableSources}"
		"${C_LIBEXEC}"
		"${CONDOR_TOOL_LIBS};condor-aws;${EXPAT_FOUND};${CURL_FOUND};${ZLIB_FOUND}"
		OFF )

	condor_daemon( annexd
		"${librarySources};${executableSources}"
		"${CONDOR_LIBS}"
		"${C_SBIN}"
		OFF )

endif()
