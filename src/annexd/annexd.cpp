#include "condor_common.h"
#include "condor_debug.h"
#include "condor_config.h"
#include "condor_daemon_core.h"
#include "subsystem_info.h"

void
doPolling() {
	dprintf( D_ALWAYS, "doPolling()\n" );
	time_t pollingBegan = time( NULL );

	//
	// To avoid entangling the annex daemon with a thicket of libaries and
	// the sort of problems the EC2 GAHP has been having, we run an external
	// tool to do the polling.  Since this external tool is re-run from
	// scratch at long intervals, its memory leaks or other problems shouldn't
	// actually cause us any grief.  We don't want to block the dameon, so
	// we don't pipe data in or out; the tool is a trusted piece of software,
	// so it can just update the collector with its results directly.  Input
	// is therefore restricted to the command-line and/or the collector.  We
	// will want to leave security tokens in their files on disk anyway, so
	// we can just pass locations in on the command-line or through the
	// collector, as becomes necessary.
	//
	/* TODO */
}

void
main_init( int /* argc */, char ** /* argv */ ) {
	dprintf( D_ALWAYS, "main_init()\n" );

	// For later, and by the command-line tool.
	// daemonCore->RegisterCommand... ( ... )

	// For now, just poll AWS regularly.
	// Units appear are seconds.
	unsigned delay = 0;
	unsigned period = param_integer( "ANNEX_POLL_INTERVAL", 300 );
	daemonCore->Register_Timer( delay, period, & doPolling, "poll the cloud" );
}

void
main_config() {
	dprintf( D_ALWAYS, "main_config()\n" );
}

void
main_shutdown_fast() {
	dprintf( D_ALWAYS, "main_shutdown_fast()\n" );
	DC_Exit( 0 );
}

void
main_shutdown_graceful() {
	dprintf( D_ALWAYS, "main_shutdown_graceful()\n" );
	DC_Exit( 0 );
}

void
main_pre_dc_init( int /* argc */, char ** /* argv */ ) {
	dprintf( D_ALWAYS, "main_pre_dc_init()\n" );
}

void
main_pre_command_sock_init() {
	dprintf( D_ALWAYS, "main_pre_command_sock_init()\n" );
}

int
main( int argc, char ** argv ) {
	set_mySubSystem( "ANNEXD", SUBSYSTEM_TYPE_DAEMON );

	dc_main_init = & main_init;
	dc_main_config = & main_config;
	dc_main_shutdown_fast = & main_shutdown_fast;
	dc_main_shutdown_graceful = & main_shutdown_graceful;
	dc_main_pre_dc_init = & main_pre_dc_init;
	dc_main_pre_command_sock_init = & main_pre_command_sock_init;

	return dc_main( argc, argv );
}
