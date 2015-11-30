%% -*- coding: utf-8 -*-
%% @author Andrey Andruschenko <apofiget@gmail.com>
%% @version 0.6
%% @doc UniFi controller API, tested with v2.4.6, v4.7.5
%% @reference <a href="http://www.ubnt.com/download/?group=unifi-ap">UniFi controller download</a>;
%% @reference <a href="http://wiki.ubnt.com/UniFi_FAQ">UniFi FAQ</a>;
%% @reference <a href="http://community.ubnt.com/t5/tkb/communitypage">UniFi community knowledge base</a>
%% @end
-module(unifi).
-author("Andrey Andruschenko <apofiget@gmail.com>").

-export([login/3, login/5, logout/1, backup/1,
         get_alerts/1, get_alerts_unarchived/1, get_events/1,
         get_events/2, get_aps/1, get_alluser/3,
         get_alluser_offline/3, get_users/1, get_users_active/1,
         get_user_groups/1, get_wlans/1, get_settings/1,
         block_client/2, unblock_client/2, disconnect_client/2,
         restart_ap/2, archive_alerts/1, auth_guest/3,
         auth_guest/5, auth_guest/6, unauth_guest/2,
         gen_voucher/3, gen_voucher/5, gen_voucher/6,
         gen_voucher_ot/3, gen_voucher_ot/5, gen_voucher_ot/6,
         get_voucher/2, del_voucher/2, get_users_active_by_ip/2,
         get_users_active_by_mac/2, get_users_active_by_propertie/3]).


-type user_type() :: all | guest | user | noted | blocked.
%% Type of controller client
-type version() :: v2 | v3.
%% Controller API version
-type opt_list() :: [option()].
-type option() :: {url, Url :: string()} | {cookie, Cookie :: string()} | {path, Path :: string()}.
%% Controller session options
-type token() :: list().
%% Voucher creation token

%% @doc Open session. Return session options or error.
%% Use it first before send other request.
%% For v2 API only
%% @end
-spec(login(Url :: string, Login :: string(), Pass :: string()) -> {ok, opt_list()} | {error, Reply :: string()}).
login(Url, Login, Pass) -> login(Url, Login, Pass, v2, "").
%% @doc Open session. Same as above, but for v3/V4 API.
%% For UniFi controller v3/V4: Version and Site required, default site name - "default"
%% @end
-spec(login(Url :: string, Login :: string(), Pass :: string(), Version :: version(), Site :: string()) -> {ok, opt_list()} | {error, Reply :: string()}).
login(Url, Login, Pass, Version, Site) ->
    try [ok,ok,ok,ok,ok] = [application:ensure_started(A) || A <- [asn1, crypto, public_key, ssl, ibrowse]] of
        _ ->
            VerDepOpts = case Version of
                             v2 -> [{path, "api/"}, {login_path, "login"},
                                    {credentials, "login=Login&username="++Login++"&password="++Pass}];
                             _  -> [{path, "api/s/" ++ Site ++ "/"}, {login_path, "api/login"},
                                    {credentials, json2:encode(json2:obj_from_list([{username, Login}, {password, Pass}]))}]
                         end,
            Reply = ibrowse:send_req(Url ++ proplists:get_value(login_path, VerDepOpts),
                                     [{"Content-Type", "application/x-www-form-urlencoded"}], post,
                                     proplists:get_value(credentials, VerDepOpts), conn_opts()),
            case [Reply, Version ] of
                [{error, Reason},_] -> {error, Reason};
                [{ok, "302",Headers, _},v2] ->
                    {ok, [
                          {url, Url},
                          {cookie, string:strip(hd(string:tokens(proplists:get_value("Set-Cookie",Headers),"")),right,$;)},
                          {path, proplists:get_value(path,VerDepOpts)}]};
                [{ok, "302",Headers, _},v3] ->
                    {ok, [
                          {url, Url},
                          {cookie, string:strip(hd(string:tokens(proplists:get_value("Set-Cookie",Headers),"")),right,$;)},
                          {path, proplists:get_value(path, VerDepOpts)}]};
                [{ok, "200", Headers, _},v4] ->
                    {ok, [
                          {url, Url},
                          {cookie, string:strip(hd(string:tokens(proplists:get_value("Set-Cookie",Headers)," ")),right,$;)},
                          {path, proplists:get_value(path, VerDepOpts)}]};
                [{ok, "200", _, _},_] -> {error, "Login failed"};
                [{ok, _, _, Body},_] -> {error, Body}
            end
    catch _:_ ->
            {error, "Some dependence application not stated"}
    end.

%% @doc Close session.
%% @end
-spec(logout(Opts :: opt_list()) -> ok | {error, Reply :: string()}).
logout(Opts) ->
    case ibrowse:send_req(proplists:get_value(url, Opts) ++ "logout", [{cookie, proplists:get_value(cookie, Opts)}], get, [], conn_opts()) of
        {ok, "302", _, _} -> ok;
        {ok, _, _, Body} -> {error, Body};
        {error, Reason} -> {error, Reason}
    end.

%% @doc Return backup of controller configuration
%% @end
-spec(backup(Opts :: opt_list()) -> {ok, File :: binary()} | {error, Reply :: string()}).
backup(Opts) ->
    case ibrowse:send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++
                              "cmd/system",
                          [{"Content-Type", "application/x-www-form-urlencoded"},
                           {cookie, proplists:get_value(cookie, Opts)}], post, <<"json={'cmd':'backup'}">> , conn_opts()) of
        {ok, "200", Headers, Body} ->
            case proplists:get_value("Content-Type", Headers) of
                "application/json" -> R = parse_json_obj(Body),
                                      case R of
                                          {ok, Obj} ->
                                              DlUrl = proplists:get_value("url", Obj),
                                              DlReply = ibrowse:send_req(proplists:get_value(url, Opts)
                                                                         ++ string:strip(DlUrl, left, $/),
                                                                         [{cookie,proplists:get_value(cookie,Opts)}],
                                                                         get, [],[ {response_format, binary}| conn_opts()]),
                                              case DlReply of
                                                  {ok, "200", _, File} -> {ok, File};
                                                  {ok, _, _, Reply} -> {error, Reply};
                                                  Any -> Any
                                              end;
                                          Any -> Any
                                      end;
                _ -> {error, Body}
            end;
        {ok, "302", _, _} -> {error, "Authorization required!"};
        {ok, _, _, Body} -> {error, Body};
        Any -> Any
    end.

%% @doc Return list of unarchived alers
%% @end
-spec(get_alerts_unarchived(Opts :: opt_list()) -> {ok, [Alers :: list()]} | {error, Reply :: string()}).
get_alerts_unarchived(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/alarm",
             proplists:get_value(cookie, Opts), <<"json={'_sort':'-time','archived':false}">>).

%% @doc Return list of all alerts
%% @end
-spec(get_alerts(Opts :: opt_list()) -> {ok, [Alers :: list()]} | {error, Reply :: string()}).
get_alerts(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/alarm",
             proplists:get_value(cookie, Opts), <<"json={'_sort':'-time'}">>).

%% @doc Archive active alerts
%% @end
-spec(archive_alerts(Opts :: opt_list()) -> {ok, [none]} | {error, Reply :: string()}).
archive_alerts(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/evtmgr",
             proplists:get_value(cookie, Opts), <<"json={'cmd':'archive-all-alarms'}">>).

%% @doc Return list of all events
%% @end
-spec(get_events(Opts :: opt_list()) -> {ok, [Events :: list()]} | {error, Reply :: string()}).
get_events(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/event",
             proplists:get_value(cookie, Opts), <<>>).

%% @doc Return list of all events within N hours
%% @end
-spec(get_events(Opts :: opt_list(), Hours :: integer()) -> {ok, [Events :: list()]} | {error, Reply :: string()}).
get_events(Opts, Hours) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/event",
             proplists:get_value(cookie, Opts), list_to_binary("json={'within':'" ++
                                                                   integer_to_list(Hours) ++ "'}")).

%% @doc Return list of AP's with options
%% @end
-spec(get_aps(Opts :: opt_list()) -> {ok, [Ap :: list()]} | {error, Reply :: string()}).
get_aps(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/device",
             proplists:get_value(cookie, Opts), <<"json={'_depth': 1, 'test': null}">>).

%% @doc Return a list of all known clients, with detailed information about each.
%% @end
-spec(get_alluser(Opts :: opt_list(), Type :: user_type(), Hours :: integer()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_alluser(Opts, Type, Hours) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/alluser",
             proplists:get_value(cookie, Opts), list_to_binary("json={'type':'"++
                                                                   atom_to_list(Type) ++"','is_offline':false,'within':'"++
                                                                   integer_to_list(Hours) ++"'}")).

%% @doc Return a list of all known offline clients, with detailed information about each.
%% @end
-spec(get_alluser_offline(Opts :: opt_list(), Type :: user_type(), Hours :: integer()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_alluser_offline(Opts, Type, Hours) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/alluser",
             proplists:get_value(cookie, Opts), list_to_binary("json={'type':'"++
                                                                   atom_to_list(Type) ++"','is_offline':true,'within':'"++
                                                                   integer_to_list(Hours) ++"'}")).

%% @doc Return a list of all known clients, with significant information about each.
%% @end
-spec(get_users(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_users(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/user",
             proplists:get_value(cookie, Opts), <<"json={}">>).

%% @doc Return a list of all active clients, with significant information about each.
%% @end
-spec(get_users_active(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_users_active(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/sta",
             proplists:get_value(cookie, Opts), <<"json={}">>).

%% @doc Return a properties list of client with given IP address.
%% @end
-spec(get_users_active_by_ip(Opts :: opt_list(), IP :: string()) -> {ok, [User :: list()]} |
                                                                    {error,Reply :: string()}).
get_users_active_by_ip(Opts, IP) ->
    get_users_active_by_propertie(Opts, "ip", IP).

%% @doc Return a properties list of client with given MAC address.
%% @end
-spec(get_users_active_by_mac(Opts :: opt_list(), MAC :: string()) -> {ok, [User :: list()]} |
                                                                      {error,Reply :: string()}).
get_users_active_by_mac(Opts, MAC) ->
    get_users_active_by_propertie(Opts, "mac", MAC).

%% @doc Return a properties list of client(s) which proppertie PropertieName
%% have a value ProppertieValue.
%% @end
-spec(get_users_active_by_propertie(Opts :: opt_list(), PropName :: string(), PropValue :: string()) -> {ok, [User :: list()]} |
                                                                                                        {error,Reply :: string()}).
get_users_active_by_propertie(Opts, PropertieName, PropertieValue) ->
    case get_users_active(Opts) of
        {ok, ClientsList} ->
            FilteredList = lists:filter(fun(E) ->
                                                case proplists:get_value(PropertieName, E) of
                                                    undefined -> false;
                                                    PropertieValue -> true;
                                                    _ -> false
                                                end
                                        end,
                                        ClientsList),
            case FilteredList of
                [] -> {ok, []};
                List -> {ok, List}
            end;
        Any -> Any
    end.

%% @doc Return a list of user groups with its settings.
%% @end
-spec(get_user_groups(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_user_groups(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/usergroup",
             proplists:get_value(cookie, Opts), <<"json={}">>).

%% @doc Return a list of wireless networks with settings.
%% @end
-spec(get_wlans(Opts :: opt_list()) -> {ok, [Wlan :: list()]} | {error, Reply :: string()}).
get_wlans(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/wlanconf",
             proplists:get_value(cookie, Opts), <<"json={}">>).

%% @doc Return a list of controller settings.
%% @end
-spec(get_settings(Opts :: opt_list()) -> {ok, [Option :: list()]} | {error, Reply :: string()}).
get_settings(Opts) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/setting",
             proplists:get_value(cookie, Opts), <<"json={}">>).

%% @doc Block wireless client with given MAC-address
%% @end
-spec(block_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
block_client(Opts, Mac) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'block-sta', 'mac':'"++ Mac ++"'}")).

%% @doc Unblock wireless client with given MAC-address
%% @end
-spec(unblock_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
unblock_client(Opts, Mac) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'unblock-sta', 'mac':'"++ Mac ++"'}")).

%% @doc Disconnect wireless client with given MAC-address, forcing them to reassociate.
%% @end
-spec(disconnect_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
disconnect_client(Opts, Mac) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'kick-sta', 'mac':'"++ Mac ++"'}")).

%% @doc Restart AP with given MAC-address.
%% @end
-spec(restart_ap(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
restart_ap(Opts, Mac) ->
    send_req(proplists:get_value(url, Opts) ++  proplists:get_value(path, Opts) ++ "cmd/devmgr",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'restart', 'mac':'"++ Mac ++"'}")).

%% @doc Authorize guest based on his MAC address.<br/>
%%   Mac     -- the guest MAC address: "aa:bb:cc:dd:ee:ff"<br/>
%%   Minutes -- duration of the authorization in minutes<br/>
%% @end
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts),
             list_to_binary("json={'cmd':'authorize-guest',
                                   'mac':'" ++ Mac ++ "','minutes':" ++ integer_to_list(Minutes) ++ "}")).

%% @doc Authorize guest based on his MAC address.<br/>
%%   Mac     -- the guest MAC address: "aa:bb:cc:dd:ee:ff"<br/>
%%   Minutes -- duration of the authorization in minutes<br/>
%%   Up      -- up speed allowed in kbps (optional)<br/>
%%   Down    -- down speed allowed in kbps (optional)<br/>
%% @end
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer(), Up :: integer(), Down :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes, Up, Down) ->
    send_req(proplists:get_value(url, Opts) ++  proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts),
             list_to_binary("json={'cmd':'authorize-guest', 'mac':'" ++ Mac ++
                                "','minutes':" ++ integer_to_list(Minutes) ++ ",'up':" ++ integer_to_list(Up) ++
                                ",'down':" ++ integer_to_list(Down) ++ "}")).
%% @doc Authorize guest based on his MAC address.<br/>
%%   Mac     -- the guest MAC address: "aa:bb:cc:dd:ee:ff"<br/>
%%   Minutes -- duration of the authorization in minutes<br/>
%%   Up      -- up speed allowed in kbps<br/>
%%   Down    -- down speed allowed in kbps<br/>
%%   Quota   -- quantity of bytes allowed in MB<br/>
%% @end
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes, Up, Down, Quota) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts),
             list_to_binary("json={'cmd':'authorize-guest', 'mac':'" ++ Mac ++
                                "','minutes':" ++ integer_to_list(Minutes) ++ ",'up':" ++ integer_to_list(Up) ++
                                ",'down':" ++ integer_to_list(Down) ++
                                ",'bytes':" ++ integer_to_list(Quota) ++ "}")).
%% @doc Unauthorize guest based on his MAC address.
%% @end
-spec(unauth_guest(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
unauth_guest(Opts, Mac) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'unauthorize-guest', 'mac':'" ++ Mac ++ "'}")).


%% @doc Generate voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot",
                  proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++
                                     integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'quota': 0}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.

%% @doc Generate voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Up      -- upload bandwith, kbps<br/>
%% Down    -- download bandwith, kbps<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count, Up, Down) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot",
                  proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++
                                     integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'up':" ++
                                     integer_to_list(Up) ++ ",'down':" ++ integer_to_list(Down) ++ ",'quota': 0}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.

%% @doc Generate voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Up      -- upload bandwith, kbps<br/>
%% Down    -- download bandwith, kbps<br/>
%% Quota   -- download quota, MB<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count, Up, Down, Quota) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++
                                     integer_to_list(Expires) ++",'n':" ++
                                     integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++
                                     integer_to_list(Down) ++ ",'bytes':" ++ integer_to_list(Quota) ++ ",'quota': 0}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.


%% @doc Generate one-time used voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++
                                     integer_to_list(Expires) ++",'n':" ++
                                     integer_to_list(Count) ++ ",'quota': 1}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.

%% @doc Generate one-time used voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Up      -- upload bandwith, kbps<br/>
%% Down    -- download bandwith, kbps<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count, Up, Down) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot",
                  proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++
                                     integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++
                                     integer_to_list(Down) ++ ",'quota': 1}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.

%% @doc Generate one-time used voucher(s)<br/>
%% Expires -- Minutes to voucher expires<br/>
%% Count   -- count vouchers to generate<br/>
%% Up      -- upload bandwith, kbps<br/>
%% Down    -- download bandwith, kbps<br/>
%% Quota   -- download quota, MB<br/>
%% Return token: create_time<br/>
%% @end
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, token()} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count, Up, Down, Quota) ->
    case send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot",
                  proplists:get_value(cookie, Opts),
                  list_to_binary("json={'cmd':'create-voucher','expire':" ++
                                     integer_to_list(Expires) ++",'n':" ++
                                     integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++
                                     integer_to_list(Down) ++ ",'bytes':" ++ integer_to_list(Quota) ++ ",'quota': 1}")) of
        {ok, P} -> {ok, integer_to_list(proplists:get_value("create_time", P))};
        Any -> Any
    end.

%% @doc Return generated voucher(s)
%% @end
-spec(get_voucher(Opts :: opt_list(), Token :: token()) -> {ok, [tuple()]} | {error, Reply :: string()}).
get_voucher(Opts, Token) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/voucher",
             proplists:get_value(cookie, Opts), list_to_binary("json={'create_time':" ++ Token ++ "}")).

%% @doc Delete generated voucher
%% @end
-spec(del_voucher(Opts :: opt_list(), Id :: string()) -> {ok, [none]} | {error, Reply :: string()}).
del_voucher(Opts, Id) ->
    send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot",
             proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'delete-voucher','_id':'" ++ Id ++ "'}")).

%% Get JSON from application service
%% @hidden
send_req(Url, Cookie, Request) ->
    case ibrowse:send_req(Url, [{"Content-Type", "application/x-www-form-urlencoded"},{cookie, Cookie}],
                          post, Request, conn_opts()) of
        {ok, "200", Headers, Body} ->
            case hd(string:tokens(proplists:get_value("Content-Type", Headers), ";")) of
                "application/json" -> parse_json_obj(Body);
                Any -> Any
            end;
        {ok, _Code, _Headers, Body} -> {error, Body};
        Any -> Any
    end.

%% SSL connection options: only crypt connection,
%% peer certificate verifycation always success
%% @hidden
conn_opts() ->
    [{is_ssl, true}, {ssl_options,[{versions,[tlsv1]}, {verify, verify_peer},
                                   {verify_fun,{fun(_,{_, _}, UserState) -> {valid, UserState} end, []}},
                                   {secure_renegotiate, true}, {depth, 4}, {fail_if_no_peer_cert, false}]}].

%% Deserialize JSON representation to Erlang proplist
%% @hidden
json2proplist(List) when is_list(List) ->
    lists:map(fun({Name, {struct, E}}) -> {Name, E};
                 ({Name, {array, [{struct, E}]}}) -> {Name, E};
                 ({Name, {array, E}}) -> {Name, E};
                 ({Name, [{struct,E}]}) -> {Name, E};
                 ({struct, L}) -> L;
                 (E) -> E end , List);
json2proplist(E) -> E.


%% Decode and parse JSON reply
%% @hidden
parse_json_obj(Json) ->
    case json2:decode_string(Json) of
        {ok, {struct, Struct}} ->
            {struct,Meta} = proplists:get_value("meta", Struct),
            ReplyCode = proplists:get_value("rc", Meta),
            case ReplyCode of
                "ok" ->
                    case proplists:get_value("data", Struct) of
                        {array,[{struct, Array}]} -> {ok, [{K,json2proplist(V)} || {K,V} <- json2proplist(Array)]};
                        {array,Structs} -> {ok, [ json2proplist(L)|| L <- json2proplist(Structs)]}
                    end;
                _ ->
                    {error, proplists:get_value("msg", Meta)}
            end;
        Any -> {error, Any}
    end.
