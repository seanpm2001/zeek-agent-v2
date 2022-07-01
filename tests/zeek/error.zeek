# @TEST-DOC: Test a basic query to the agent.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -L debug -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeek/reporter.log | zeek-cut -n location >reporter.log
# @TEST-EXEC: btest-diff reporter.log

@load test-setup

event got_result()
	{ }

event zeek_init()
	{
	ZeekAgent::query([$sql_stmt="SELECT foo FROM bar", $event_=got_result]);
	}

event ZeekAgentAPI::agent_error_v1(ctx: ZeekAgent::Context, msg: string)
	{
	terminate();
	}
