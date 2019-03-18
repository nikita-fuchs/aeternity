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
             {running_apps(), loaded_apps()}
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

running_apps() ->
    lists:map(fun({A,_,_}) -> A end, application:which_applications()).

loaded_apps() ->
    lists:map(fun({A,_,_}) -> A end, application:loaded_applications()).

restore_stopped_and_unloaded_apps(OldRunningApps, OldLoadedApps) ->
    BadRunningApps = running_apps() -- OldRunningApps,
    lists:foreach(fun(A) -> ok = application:stop(A) end, BadRunningApps),
    BadLoadedApps = loaded_apps() -- OldLoadedApps,
    lists:foreach(fun(A) -> ok = application:unload(A) end, BadLoadedApps),
    OldRunningApps = running_apps(),
    OldLoadedApps = loaded_apps(),
    ok.
