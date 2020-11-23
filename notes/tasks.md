# Tasks

Tasks are the basis of the nihilo RPC model. They each represent a call to a function in a specific machine, originating from a specific machine. Tasks are represented as collections keys and values, a simple task follows;

```
id:8a2d4366f999196655c78c3864f16769
origin:~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
dest:~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
function:hello_world
```

`on_success`, `on_failure` and `param` can all be added to specify more behaviour.

## Inter-host calls

When a call occurs between hosts, A task goes though several transformations. Consider the following task on the caller host;

```
id:c5f5cc25f7079aa5cbf11465a777fc53
origin:~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
dest:example.com~698da48903c729465bb531ff9e1d9f18e99de186dc27ed609b431c632822024d
function:hello_world
on_success:successful_retrieval
```

Prior to transmission, the task must be edited into the task sent to the callee. Origin and dest public keys are embedded only during session creation, and so nihilo machine addresses are unecassary at other times. Instead of forwarding the specific function name for the success and failure conditions, a copy of the task is kept on the caller host.

```
id:c5f5cc25f7079aa5cbf11465a777fc53
function:hello_world
handles_success:yes
handles_failure:no
```

This will transit to the other host, and become this once it is received (where `XXX.XXX.XXX.XXX` is the caller's IP):

```
id:c5f5cc25f7079aa5cbf11465a777fc53
origin:XXX.XXX.XXX.XXX~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
dest:~698da48903c729465bb531ff9e1d9f18e99de186dc27ed609b431c632822024d
function:hello_world
handles_success:yes
handles_failure:no
```

This will execute and amend the task to be returned to the caller;

```
id:c5f5cc25f7079aa5cbf11465a777fc53
origin:XXX.XXX.XXX.XXX~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
dest:~698da48903c729465bb531ff9e1d9f18e99de186dc27ed609b431c632822024d
status:success
param:hello, world!
```

This will be edited for transit:

```
id:c5f5cc25f7079aa5cbf11465a777fc53
status:success
param:hello, world!
```

And will be combined with the original task stored against the session on the caller host to create a new task:

```
id:73a3ecf50d44766aa84ad6d35d2dfc4e
origin:example.com~698da48903c729465bb531ff9e1d9f18e99de186dc27ed609b431c632822024d
dest:~b32c30d4b4111fe997c6f3a0b61956010b7a3e32e42360fa4617a120f12883df
function:successful_retrieval
param:hello, world!
```