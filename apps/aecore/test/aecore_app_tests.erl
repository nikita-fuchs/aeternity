-module(aecore_app_tests).

-include_lib("eunit/include/eunit.hrl").
-include("blocks.hrl").

persisted_valid_gen_block_test_() ->
    {foreach,
     fun() ->
             meck:new(aec_db, [passthrough]),
             meck:expect(aec_db, load_database, 0, ok),
             meck:new(aecore_sup, [passthrough]),
             meck:expect(aecore_sup, start_link, 0, {ok, pid}),
             meck:new(aec_jobs_queues, [passthrough]),
             meck:expect(aec_jobs_queues, start, 0, ok),
             lager:start(),
             {running_applications(), application:loaded_applications()}
     end,
     fun({OldRunningApps, OldLoadedApps}) ->
             ok = restore_stopped_and_unloaded_apps(OldRunningApps, OldLoadedApps),
             ok = application:stop(lager),
             meck:unload(aec_jobs_queues),
             meck:unload(aecore_sup),
             meck:unload(aec_db)
     end,
     [{"Check persisted genesis block",
       fun() ->
            meck:expect(aec_db, persisted_valid_genesis_block, 0, false),
            ?assertEqual({error, inconsistent_database},
                         aecore_app:start(normal, [])),

            meck:expect(aec_db, persisted_valid_genesis_block, 0, true),
            ?assertEqual({ok, pid}, aecore_app:start(normal, [])),
            ok
       end}
     ]}.

running_applications() ->
    lists:map(fun({A,_,_}) -> A end, application:which_applications()).

restore_stopped_and_unloaded_apps(OldRunningApps, OldLoadedApps) ->
    restore_stopped_and_unloaded_apps_(OldRunningApps, OldLoadedApps, 1).

restore_stopped_and_unloaded_apps_(OldRunningApps, OldLoadedApps, 0) ->
    {error, {unexpectedly_running_apps(OldRunningApps), unexpectedly_loaded_apps(OldLoadedApps)}};
restore_stopped_and_unloaded_apps_(OldRunningApps, OldLoadedApps, Attempts) ->
    BadRunningApps = unexpectedly_running_apps(OldRunningApps),
    BadLoadedApps = unexpectedly_loaded_apps(OldLoadedApps),
    case lists:all(fun(A) -> application:stop(A) =:= ok end, BadRunningApps) andalso lists:all(fun(A) -> application:unload(A) =:= ok end, BadLoadedApps) of
        false ->
            restore_stopped_and_unloaded_apps_(OldRunningApps, OldLoadedApps, Attempts - 1);
        true ->
            OldRunningApps = running_applications(),
            OldLoadedApps = application:loaded_applications(),
            ok
    end.

unexpectedly_running_apps(OldRunningApps) ->
    running_applications() -- OldRunningApps.

unexpectedly_loaded_apps(OldLoadedApps) ->
    application:loaded_applications() -- OldLoadedApps.
