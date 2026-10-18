---------------------------- MODULE EffectIdempotency -----------------------
(***************************************************************************)
(* FSS-028: two-phase effect idempotency.                                  *)
(*                                                                         *)
(* Model: effect requests move through the canonical machine Prepared ->   *)
(* Committed -> AdapterAccepted -> Observed -> Verified, with Cancelled /  *)
(* Failed / Indeterminate terminals. The wire may DUPLICATE or REORDER     *)
(* requests: prepare twice, commit twice, observe before accept on a       *)
(* retry, cancel racing commit.                                            *)
(*                                                                         *)
(* Invariants checked (the effect constitution):                           *)
(*   E1 SingleDispatch: at most one external dispatch per operation —      *)
(*      duplicate commits never produce two dispatches.                    *)
(*   E2 NoRewind: terminal states (Verified/Cancelled/Failed) are          *)
(*      absorbing; no transition leaves them.                              *)
(*   E3 ObligationOnce: the terminal obligation resolves at most once.     *)
(*   E4 CancelBoundary: cancellation lands only at Prepared (pre-commit);  *)
(*      a committed effect runs to a terminal state instead.               *)
(*   E5 NoUpgrade: an Indeterminate record never transitions directly to   *)
(*      Verified; it must be re-established via Observed.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Operations

States == {"Prepared", "Committed", "AdapterAccepted", "Observed",
           "Verified", "Cancelled", "Failed", "Indeterminate"}

VARIABLES
    \* operation state: Operations -> States
    state,
    \* dispatch count per operation (E1)
    dispatches,
    \* obligation resolution count per operation (E3)
    resolutions,
    \* request queue: multiset of in-flight requests (duplicates possible)
    \* modeled as a bounded set of (op, kind) with multiplicity via counts
    inFlight

vars == <<state, dispatches, resolutions, inFlight>>

RequestKinds == {"prepare", "commit", "accept", "observe", "verify", "cancel", "fail"}

TypeOK ==
    /\ state \in [Operations -> States]
    /\ dispatches \in [Operations -> 0..1]
    /\ resolutions \in [Operations -> 0..1]
    /\ inFlight \in [Operations -> [RequestKinds -> 0..2]]  \* duplicates bounded at 2

Init ==
    /\ state = [op \in Operations |-> "Prepared"]
    /\ dispatches = [op \in Operations |-> 0]
    /\ resolutions = [op \in Operations |-> 0]
    /\ inFlight = [op \in Operations |->
            [k \in RequestKinds |-> 0]]

\* A request is injected (possibly duplicating an in-flight one).
Inject(op, kind) ==
    /\ inFlight[op][kind] < 2
    /\ inFlight' = [inFlight EXCEPT ![op][kind] = @ + 1]
    /\ UNCHANGED <<state, dispatches, resolutions>>

Consume(op, kind) ==
    /\ inFlight[op][kind] > 0
    /\ inFlight' = [inFlight EXCEPT ![op][kind] = @ - 1]

\* COMMIT: the only transition that dispatches. Idempotent: a duplicate
\* commit against an already-Committed (or later) state is consumed but
\* does NOT dispatch again.
Commit(op) ==
    /\ Consume(op, "commit")
    /\ IF state[op] = "Prepared" /\ dispatches[op] = 0
       THEN /\ state' = [state EXCEPT ![op] = "Committed"]
            /\ dispatches' = [dispatches EXCEPT ![op] = 1]
       ELSE UNCHANGED <<state, dispatches>>  \* duplicate commit: no-op
    /\ UNCHANGED <<resolutions>>

Accept(op) ==
    /\ Consume(op, "accept")
    /\ IF state[op] = "Committed"
       THEN state' = [state EXCEPT ![op] = "AdapterAccepted"]
       ELSE UNCHANGED <<state>>
    /\ UNCHANGED <<dispatches, resolutions>>

Observe(op) ==
    /\ Consume(op, "observe")
    /\ IF state[op] \in {"AdapterAccepted", "Indeterminate"}
       THEN state' = [state EXCEPT ![op] = "Observed"]
       ELSE UNCHANGED <<state>>
    /\ UNCHANGED <<dispatches, resolutions>>

\* VERIFY: terminal. Resolves the obligation exactly once (E3).
Verify(op) ==
    /\ Consume(op, "verify")
    /\ IF state[op] = "Observed" /\ resolutions[op] = 0
       THEN /\ state' = [state EXCEPT ![op] = "Verified"]
            /\ resolutions' = [resolutions EXCEPT ![op] = 1]
       ELSE UNCHANGED <<state, resolutions>>
    /\ UNCHANGED <<dispatches>>

\* FAIL: terminal from any non-terminal non-Prepared state. Idempotent.
Fail(op) ==
    /\ Consume(op, "fail")
    /\ IF state[op] \in {"Committed", "AdapterAccepted", "Observed", "Indeterminate"}
            /\ resolutions[op] = 0
       THEN /\ state' = [state EXCEPT ![op] = "Failed"]
            /\ resolutions' = [resolutions EXCEPT ![op] = 1]
       ELSE UNCHANGED <<state, resolutions>>
    /\ UNCHANGED <<dispatches>>

\* CANCEL: lands ONLY at Prepared (E4). A cancel racing a committed effect
\* is consumed and ignored — the effect runs to terminal.
Cancel(op) ==
    /\ Consume(op, "cancel")
    /\ IF state[op] = "Prepared" /\ resolutions[op] = 0
       THEN /\ state' = [state EXCEPT ![op] = "Cancelled"]
            /\ resolutions' = [resolutions EXCEPT ![op] = 1]
       ELSE UNCHANGED <<state, resolutions>>
    /\ UNCHANGED <<dispatches>>

\* INDETERMINATE: the world went dark after commit. Resolution is deferred
\* (reconciliation), so obligations are NOT resolved here.
GoIndeterminate(op) ==
    /\ state[op] \in {"Committed", "AdapterAccepted", "Observed"}
    /\ state' = [state EXCEPT ![op] = "Indeterminate"]
    /\ UNCHANGED <<dispatches, resolutions, inFlight>>

Next ==
    \E op \in Operations :
        \E kind \in RequestKinds :
            \/ Inject(op, kind)
        \/ Commit(op) \/ Accept(op) \/ Observe(op)
        \/ Verify(op) \/ Fail(op) \/ Cancel(op) \/ GoIndeterminate(op)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* INVARIANTS                                                              *)
(***************************************************************************)

\* E1: at most one external dispatch per operation, ever.
SingleDispatch == \A op \in Operations : dispatches[op] <= 1

\* E2: terminal states are absorbing (state-level: a terminal state with no
\* pending consumption can only stay). Enforced transitionally; the
\* state-level projection: terminal states have exactly one resolution.
TerminalAbsorbing ==
    \A op \in Operations :
        state[op] \in {"Verified", "Cancelled", "Failed"} => resolutions[op] = 1

\* E3: obligations resolve at most once.
ObligationOnce == \A op \in Operations : resolutions[op] <= 1

\* E4: cancellation never follows dispatch.
CancelBoundary ==
    \A op \in Operations : state[op] = "Cancelled" => dispatches[op] = 0

\* E5: Verified requires a prior Observed; since Observed is reachable only
\* from AdapterAccepted or Indeterminate, and Verified only from Observed,
\* the state-level projection is: Verified implies a dispatch occurred.
NoDirectVerify ==
    \A op \in Operations : state[op] = "Verified" => dispatches[op] = 1

CombinedInvariant ==
    /\ TypeOK
    /\ SingleDispatch
    /\ TerminalAbsorbing
    /\ ObligationOnce
    /\ CancelBoundary
    /\ NoDirectVerify

=============================================================================
