-module(sha256).
-export([hexdigest/1]).
-define(INITIAL_DIGEST, [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]).
-define(ROUND_CONSTANTS, [
  1116352408, 1899447441, 3049323471, 3921009573,  961987163, 1508970993, 2453635748, 2870763221, 3624381080,  310598401,
   607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,  264347078,  604807628,
   770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
   113926993,  338241895,  666307205,  773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
  2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909,  275423344,  430227734,  506948616,
   659060556,  883997877,  958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
  2428436474, 2756734187, 3204031479, 3329325298
]).

hexdigest(Message) ->
  process_chunks(chunk_message(pad_message(Message))).

%% ---------------------------------------------
%% UTIL
%% ---------------------------------------------
pad32(X) ->
  (X band 4294967295).

right_rotate32(X,N) ->
  (X bsr N) bor pad32(X bsl (32 - N)).

sum32(List) ->
  lists:foldl(fun(X, Acc) -> pad32(X + Acc) end, 0, List).

majority(A,B,C) ->
  A band (B bor C) bor B band C.

%% ---------------------------------------------
%% MESSAGE PADDING
%% ---------------------------------------------

pad_message(Message) ->
  lists:append(Message, extra_bytes(length(Message))).

extra_bytes(Len) ->
  lists:append([separator_byte(), pad_bytes(Len), len_bytes(Len)]).

separator_byte() ->
  [128].

pad_bytes(Len) ->
  lists:duplicate(64 - ((Len + 9) rem 64), 0).

len_bytes(Len) ->
  fill_with_zeros(binary_to_list(binary:encode_unsigned(Len * 8, big)), 8).

fill_with_zeros(List, Pad) ->
  lists:append([
    lists:duplicate(Pad - (length(List) rem Pad), 0),
    List
  ]).

%% ---------------------------------------------
%% MESSAGE CHUNKING
%% ---------------------------------------------

chunk_message(Message) ->
  slice_16(byte_list_to_word_list(Message)).

byte_list_to_word_list(ByteList) ->
  byte_list_to_word_list([], ByteList).

byte_list_to_word_list(WordList, []) ->
  WordList;
byte_list_to_word_list(WordList, [B1, B2, B3, B4 | ByteList]) ->
  byte_list_to_word_list(WordList ++ [bytes_to_word(B1, B2, B3, B4)], ByteList).

bytes_to_word(A,B,C,D) ->
  (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

slice_16(UnslicedList) ->
  slice_16([], UnslicedList).

slice_16(SlicedList, []) ->
  SlicedList;
slice_16(SlicedList, [A,B,C,D, E,F,G,H, I,J,K,L, M,N,O,P | WordList]) ->
  slice_16(SlicedList ++ [[A,B,C,D, E,F,G,H, I,J,K,L, M,N,O,P]], WordList).

%% ---------------------------------------------
%% INTERATIONS
%% ---------------------------------------------

process_chunks(Chunks) ->
  lists:foldl(
    fun(Chunk, Digest) -> process_chunk(Digest, Chunk) end,
    ?INITIAL_DIGEST,
    Chunks
  ).

process_chunk(Digest, State) ->
  lists:map(
    fun({A, B}) -> pad32(A + B) end,
    lists:zip(Digest, sha256_iterate(complete_state(State), Digest))
  ).

complete_state(State) ->
  complete_state(State, 0).

complete_state(State, 48) ->
  State;
complete_state(State, Idx) ->
  S0 = right_rotate32(lists:nth(Idx+2, State), 7) bxor right_rotate32(lists:nth(Idx+2, State), 18) bxor (lists:nth(Idx+2, State) bsr 3),
  S1 = right_rotate32(lists:nth(Idx+15, State), 17) bxor right_rotate32(lists:nth(Idx+15, State), 19) bxor (lists:nth(Idx+15, State) bsr 10),
  El = sum32([lists:nth(Idx+1, State), S0, lists:nth(Idx+10, State), S1]),
  complete_state(State ++ [El], Idx+1).

sha256_iterate(State, Digest) ->
  lists:foldl(fun(Idx, IDigest) -> sha256_inner_iterate(Idx, IDigest, State) end, Digest, lists:seq(1, 64)).

sha256_inner_iterate(Idx, Digest, State) ->
  Ch = lists:nth(5, Digest) band lists:nth(6, Digest) bxor (bnot lists:nth(5, Digest)) band lists:nth(7, Digest),
  S0 = right_rotate32(lists:nth(1, Digest), 2) bxor right_rotate32(lists:nth(1, Digest), 13) bxor right_rotate32(lists:nth(1, Digest), 22),
  S1 = right_rotate32(lists:nth(5, Digest), 6) bxor right_rotate32(lists:nth(5, Digest), 11) bxor right_rotate32(lists:nth(5, Digest), 25),
  T1 = sum32([
    lists:nth(8, Digest),
    S1,
    Ch,
    lists:nth(Idx, ?ROUND_CONSTANTS),
    lists:nth(Idx, State)
  ]),
  T2 = sum32([
    S0,
    majority(lists:nth(1, Digest), lists:nth(2, Digest), lists:nth(3, Digest))
  ]),
  [
    sum32([T1, T2]),
    lists:nth(1, Digest),
    lists:nth(2, Digest),
    lists:nth(3, Digest),
    sum32([lists:nth(4, Digest), T1]),
    lists:nth(5, Digest),
    lists:nth(6, Digest),
    lists:nth(7, Digest)
  ].
