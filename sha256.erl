-module(sha256).
-export([digest/1, hexdigest/1]).
-define(INITIAL_DIGEST, [
  16#6A09E667, 16#BB67AE85, 16#3C6EF372, 16#A54FF53A, 16#510E527F, 16#9B05688C, 16#1F83D9AB, 16#5BE0CD19
]).
-define(ROUND_CONSTANTS(X), lists:nth(X, [
  16#428A2F98, 16#71374491, 16#B5C0FBCF, 16#E9B5DBA5, 16#3956C25B, 16#59F111F1, 16#923F82A4, 16#AB1C5ED5,
  16#D807AA98, 16#12835B01, 16#243185BE, 16#550C7DC3, 16#72BE5D74, 16#80DEB1FE, 16#9BDC06A7, 16#C19BF174,
  16#E49B69C1, 16#EFBE4786, 16#0FC19DC6, 16#240CA1CC, 16#2DE92C6F, 16#4A7484AA, 16#5CB0A9DC, 16#76F988DA,
  16#983E5152, 16#A831C66D, 16#B00327C8, 16#BF597FC7, 16#C6E00BF3, 16#D5A79147, 16#06CA6351, 16#14292967,
  16#27B70A85, 16#2E1B2138, 16#4D2C6DFC, 16#53380D13, 16#650A7354, 16#766A0ABB, 16#81C2C92E, 16#92722C85,
  16#A2BFE8A1, 16#A81A664B, 16#C24B8B70, 16#C76C51A3, 16#D192E819, 16#D6990624, 16#F40E3585, 16#106AA070,
  16#19A4C116, 16#1E376C08, 16#2748774C, 16#34B0BCB5, 16#391C0CB3, 16#4ED8AA4A, 16#5B9CCA4F, 16#682E6FF3,
  16#748F82EE, 16#78A5636F, 16#84C87814, 16#8CC70208, 16#90BEFFFA, 16#A4506CEB, 16#BEF9A3F7, 16#C67178F2
])).

digest(Message) ->
  [ D1, D2, D3, D4, D5, D6, D7, D8 ] = base_digest(Message),
  binary_to_list(<< D1:32, D2:32, D3:32, D4:32, D5:32, D6:32, D7:32, D8:32 >>).

hexdigest(Message) ->
  lists:flatten([io_lib:format("~8.16.0b", [X]) || X <- base_digest(Message)]).

base_digest(Message) when is_binary(Message) ->
  process_message(pad_message(Message));
base_digest(Message) ->
  base_digest(list_to_binary(Message)).

%% ---------------------------------------------
%% UTIL
%% ---------------------------------------------

pad32(X) -> (X band 16#FFFFFFFF).
right_rotate32(X,N) -> (X bsr N) bor pad32(X bsl (32 - N)).
majority(A,B,C) -> A band (B bor C) bor B band C.

%% ---------------------------------------------
%% MESSAGE PADDING
%% ---------------------------------------------

pad_message(Message) ->
  Len = size(Message) * 8,
  Pad = 512 - (Len + 8 + 64) rem 512,
  << Message/binary, 16#80:8, 0:Pad, Len:64 >>.

%% ---------------------------------------------
%% INTERATIONS
%% ---------------------------------------------

process_message(Message) ->
  process_message(split_binary(Message, 64), ?INITIAL_DIGEST).
process_message({ Chunk, <<>> }, Digest) ->
  process_chunk(Chunk, Digest);
process_message({ Chunk, Remaining }, Digest) ->
  process_message(split_binary(Remaining, 64), process_chunk(Chunk, Digest)).

process_chunk(State, Digest) ->
  NextDigest = sha256_iterate(complete_state(State), Digest),
  lists:map(fun({ A, B }) -> pad32(A + B) end, lists:zip(Digest, NextDigest)).

complete_state(State) ->
  complete_state(State, 16).
complete_state(State, 64) ->
  State;
complete_state(State, Idx) ->
  Offset = 32 * (Idx - 16),
  << _:Offset, Word1:32, Word2:32, _:224, Word3:32, _:128, Word4:32, _/binary >> = State,
  S0 = right_rotate32(Word2, 7) bxor right_rotate32(Word2, 18) bxor (Word2 bsr 3),
  S1 = right_rotate32(Word4, 17) bxor right_rotate32(Word4, 19) bxor (Word4 bsr 10),
  El = pad32(Word1 + S0 + Word3 + S1),
  complete_state(<< State/binary, El:32 >>, Idx+1).

sha256_iterate(State, Digest) ->
  sha256_iterate(1, Digest, State).
sha256_iterate(65, Digest, _) ->
  Digest;
sha256_iterate(Idx, Digest, State) ->
  StateOffset = 32 * (Idx - 1),
  << _:StateOffset, StateKey:32, _/binary >> = State,
  [ D1, D2, D3, D4, D5, D6, D7, D8 ] = Digest,
  Ch = D5 band D6 bxor (bnot D5) band D7,
  S0 = right_rotate32(D1, 2) bxor right_rotate32(D1, 13) bxor right_rotate32(D1, 22),
  S1 = right_rotate32(D5, 6) bxor right_rotate32(D5, 11) bxor right_rotate32(D5, 25),
  T1 = pad32(D8 + S1 + Ch + ?ROUND_CONSTANTS(Idx) + StateKey),
  T2 = pad32(S0 + majority(D1, D2, D3)),
  sha256_iterate(Idx + 1, [ pad32(T1 + T2), D1, D2, D3, pad32(D4 + T1), D5, D6, D7 ], State).
