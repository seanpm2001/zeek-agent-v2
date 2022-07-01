# @TEST-DOC: Test the `sockets` table script end-to-end with mock data.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} ${PACKAGE}/table/sockets.zeek %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -M -N -L info -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeek/zeek-agent-sockets.log | zeek-cut -cn host >tmp && mv tmp zeek/zeek-agent-sockets.log
# @TEST-EXEC: btest-diff zeek/zeek-agent-sockets.log

@load test-setup

redef ZeekAgent_Sockets::subscription = ZeekAgent::SnapshotPlusDifferences;

# We only accept the 1st write writer so that our output doesn't depend on
# runtime duration.
global already_logged = F;

hook ZeekAgent_Sockets::log_policy(rec: any, id: Log::ID, filter: Log::Filter)
	{
	if ( already_logged )
		break;
	else
		already_logged = T;
	}

event do_terminate()
	{
	terminate();
	}

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context,
    columns: ZeekAgentAPI::AgentHelloV1)
	{
	schedule 2 secs { do_terminate() };
	}
