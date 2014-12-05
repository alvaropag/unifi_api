REBAR = `which rebar`

compile:
	@(if test ! -d "deps"; then mkdir deps ; fi)
	@$(REBAR) get-deps
	@$(REBAR) compile

clean:
	@$(REBAR) clean
	@rm -f erl_crash.dump

start:
	ERL_LIBS=deps erl -pa ebin deps/*/ebin -sname unifi_api

.PHONY: compile
