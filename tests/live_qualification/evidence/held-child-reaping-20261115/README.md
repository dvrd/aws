# Qualification held-child reaping

The capture owner previously called killpg unconditionally after a successful
wait had released the child's PID, permitting a post-reap group signal. Capture
now signals and waits only while its exclusively owned child returncode is still
unknown. A completed wait never leads to another signal. Pipe close also runs
when cleanup wait fails. Fixed AWS CLI commands do not intentionally leave
persistent descendants; no general debugger/process-tree framework is added.

Six mocked controls cover success/no post-reap signal, timeout kill-before-wait,
output overflow, already exited group, an exception after reaping, and cleanup
wait failure with pipe close. The original code produces3 expected failures;
the narrow fix passes all6. No subprocess, CLI, native or provider execution.
SDK/runtime/API behavior, credentials, request/deadline limits and intents remain
unchanged. The frozen readiness plan is untouched and needs a separately pinned
successor before any execution.
