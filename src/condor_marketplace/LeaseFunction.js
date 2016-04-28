var response = require( 'cfn-response' );
exports.handler = function( event, context ) {
	console.log( "Received request:\n", JSON.stringify( event ) );

	function SendFailedResponse( message, error ) {
		console.log( message );
		if( error ) { console.log( error, error.stack ); }
		var responseData = { Error : message };
		response.send( event, context, response.FAILED, responseData, message );
	}

	var stackName = event.ResourceProperties.StackName;
	if(! stackName) {
		SendFailedResponse( 'Stack name not specified' );
		return;
	}

	if( event.RequestType == 'Create' ) {
		console.log( "Received create request." );

		var leaseFunctionArn = event.ResourceProperties.LeaseFunctionArn;
		if(! leaseFunctionArn) {
			SendFailedResponse( 'Lease function ARN not specified' );
			return;
		}

		var leaseFunctionName = event.ResourceProperties.LeaseFunctionName;
		if(! leaseFunctionName) {
			SendFailedResponse( 'Lease function name not specified' );
			return;
		}

		var AWS = require( 'aws-sdk' );
		var cwe = new AWS.CloudWatchEvents();
		var params = {
			Name : 'LeaseTimer-' + stackName,
			ScheduleExpression : 'rate(1 minute)',
			State : 'ENABLED'
		};

		cwe.putRule( params, function( error, data ) {
			if( error ) {
				SendFailedResponse( 'putRule() call failed', error );
				return;
			}

			var timerArn = data.RuleArn;
			params = {
				Rule : 'LeaseTimer-' + stackName,
				Targets : [
					{
						Arn : leaseFunctionArn,
						Id : '0',
						Input : '{ "RequestType" : "Timer", "ResourceProperties" : { "StackName" : "' + stackName + '"} }'
					}
				],
			};
			cwe.putTargets( params, function( error, data ) {
				if( error ) {
					SendFailedResponse( 'putTargets() call failed', error );
					return;
				}

				var lambda = new AWS.Lambda();
				var params = {
					Action : 'lambda:InvokeFunction',
					FunctionName : leaseFunctionName,
					Principal : "events.amazonaws.com",
					StatementId : 'TimerPermission',
					SourceArn : timerArn
				};
				lambda.addPermission( params, function( error, data ) {
					if( error ) {
						SendFailedResponse( "addPermission() call failed", error );
						return;
					}

					response.send( event, context, response.SUCCESS );
					return;
				});
			});
		});
	} else if( event.RequestType == 'Delete' ) {
		console.log( "Received delete request." );

		var AWS = require( 'aws-sdk' );
		var cwe = new AWS.CloudWatchEvents();

		var params = {
			Rule : 'LeaseTimer-' + stackName,
			Ids : [ '0' ]
		};
		cwe.removeTargets( params, function( error, data ) {
			if( error ) {
				SendFailedResponse( 'removeTargets() call failed', error );
				return;
			}

			var params = {
				Name : 'LeaseTimer-' + stackName
			};
			cwe.deleteRule( params, function( error, data ) {
				if( error ) {
					SendFailedResponse( 'deleteRule() call failed', error );
					return;
				}

				response.send( event, context, response.SUCCESS );
				return;
			});
		});
	} else if( event.RequestType == 'Timer' ) {
		// FIXME: Check to see if the lease has expired.
		console.log( "Checking to see if the lease has expired on '" + stackName + "'..." );

		context.succeed();
		return;
	} else {
		console.log( "Ignoring unknown request '" + event.RequestType + "'." );
		response.send( event, context, response.SUCCESS );
		return;
	}
}
