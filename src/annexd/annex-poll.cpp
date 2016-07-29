#include "condor_common.h"
#include "condor_config.h"
#include "subsystem_info.h"
#include "condor_debug.h"

#include "condor_query.h"
#include "dc_collector.h"

#include "condor-aws.h"

bool
getAllStacks( AWS::StackMap & stacks ) {
	// Ask AWS about all of our stacks.  Each annex is contained by a stack,
	// but not all stacks will be annexes, so look for the ones with a
	// "ProjectID" tag.  For now, consider only "live" stacks; we may be
	// interested in dead ones later, for closure (on leases).

	// [TODO]  aws --region <region> describe-stacks
	// [TODO]  Extract stack ID, projectID (tag), size (parameter).

	return false;
}

bool
getAllAnnexAds( ClassAdList & ads ) {
	CondorQuery query( GENERIC_AD );
	// We may eventually add an ANNEX_AD type.  [TODO]  Until then, fake it.

	DCCollector defaultCollector;
	char * pool = defaultCollector.addr();
	if(! pool) {
		dprintf( D_ALWAYS, "Unable to locate default collector.\n" );
		return false;
	}
	dprintf( D_FULLDEBUG, "Found default collector at %s.\n", pool );

	CondorError errorStack;
	QueryResult queryResult = query.fetchAds( ads, pool, & errorStack );
	dprintf( D_FULLDEBUG, "Query result was %d.\n", queryResult );

	return queryResult == Q_OK;
}

void
pollAnnex() {
	//
	// We don't care about annex instances that have succesfully reported
	// to the collector; those can be monitored as normal.  What we're
	// looking for is annexes which are smaller than they should be.
	//
	// To begin, then, we need a list of all of our annexes.  We obtain this
	// list from the collector, but we also compare it to the truth of the
	// list obtained from the cloud.  There shouldn't be any annexes in the
	// cloud that we don't know about (since we insert an annex ad before
	// creating the annex), but we may have recorded annexes that don't
	// exist yet or whose lease has expired since the last poll.  We mark
	// the former by updating an annex's ad after we've created it.
	//
	// Having obtained a list of all our annexes, we then obtain the list
	// of instances in each annex, and compare it to the list of startds
	// advertising that ProjectID.  We then insert/update an ad for each
	// missing instance (and warn about startds reporting a ProjectID that
	// doens't claim to contain them).
	//
	// We also check the Spot instance requests for each annex, and report
	// aggregate information about them.  (For now, we don't want to add
	// another ad type to store information in the collector about each
	// Spot instance request, and we can't store the information in a startd
	// ad, because we don't have enough information to produce one that will
	// be automatically replaced by the corresponding startd when it joins
	// the pool.)  If we somehow end up where the number of "hung" Spot
	// requests plus the number of active instances is larger than the
	// requested size of the pool, that probably signals a problem, and
	// we warn about that.
	//

	// Begin by obtaining all of the annex ads.
	ClassAdList annexAds;
	if(! getAllAnnexAds( annexAds )) {
		dprintf( D_ALWAYS, "Failed to get annex ads from the collector, aborting.\n" );
		exit( 1 );
	}
	dprintf( D_FULLDEBUG, "Found %d annex ads in collector.\n", annexAds.MyLength() );

	// Obtain the cloud's list of our annexes.
	AWS::StackMap stacks;
	if(! getAllStacks( stacks )) {
		dprintf( D_ALWAYS, "Failed to get stacks from AWS, aborting.\n" );
		exit( 1 );
	}
	dprintf( D_FULLDEBUG, "Found %lu stacks in AWS.\n", stacks.size() );

	// Check the list of annexes we know about from collector against the
	// list of annexes that AWS thinks we have.
	annexAds.Rewind();
	ClassAd * annexAd;
	AWS::StackMap unknownStacks = stacks;
	while( (annexAd = annexAds.Next()) != NULL ) {
		std::string projectID;
		if(! annexAd->LookupString( "ProjectID", projectID )) {
			dprintf( D_ALWAYS, "WARNING: skipping annex ad without project ID.\n" );
			continue;
		}
		AWS::StackMap::iterator i = unknownStacks.find( projectID );
		if( i == unknownStacks.end() ) {
			// [TODO]  We should be able to tell from the annex ad if the
			// lease should have expired.  Say so, if that's the case.
			// [TODO]  If the annex doesn't say that the stack has been
			// created yet, don't warn about it not being found.
			dprintf( D_ALWAYS, "WARNING: annex %s was not found at AWS.\n", projectID.c_str() );
		} else {
			unknownStacks.erase( i );
		}
	}
	for( AWS::StackMap::const_iterator i = unknownStacks.begin(); i != unknownStacks.end(); ++i ) {
		dprintf( D_FULLDEBUG, "WARNING: found new stack %s.\n", i->first.c_str() );
	}

	// [TODO] Compare the reported desired size of each annex against the
	// desired size from the collector.

	// [TODO]  Look for missing instances.

	// [TODO]  Look up and report on the spot instance requests.

	// [TODO]  Insert (or update) the missing-instance ads and the new annex ads.
}

int
main( int argc, char ** argv ) {
	// Get dprintf() and param() working.
	set_mySubSystem( "ANNEXP", SUBSYSTEM_TYPE_DAEMON );
	config();
	dprintf_config( "ANNEX_POLLING" );

	dprintf( D_ALWAYS, "Polling...\n" );
	pollAnnex();
	dprintf( D_ALWAYS, "...done.\n" );

	return 0;
}
