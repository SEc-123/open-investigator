# Java Memory Deep Dive

Open Investigator handles Java memory-shell investigations in three explicit layers.

## 1. Default outer investigation

Default commands are low-impact:

```bash
oi java -s 14d
oi mem -s 14d
```

They collect Java process context, JVM startup arguments, `-javaagent`, `-agentlib`, JDWP, `Xbootclasspath`, `jps`, `jcmd VM.command_line`, web logs, recent JSP/JAR/WAR/CLASS changes, and process/network/file context.

This layer does not heap dump, JFR dump, or intentionally attach for internal JVM state.

## 2. Explicit JVM internal inspection

Use this only when approved for the target service:

```bash
oi mem -s 14d -m inv --java-deep
oi java -s 14d -m inv --java-deep
```

When enabled, `oi` collects bounded JVM internal diagnostics where the local JDK tooling is available:

```text
jcmd <pid> Thread.print -l
jcmd <pid> GC.class_histogram
jcmd <pid> VM.classloader_stats
jcmd <pid> VM.system_properties
jcmd <pid> VM.flags
jcmd <pid> JFR.check
```

If `jcmd` is unavailable, it attempts non-dump fallbacks:

```text
jstack -l <pid>
jmap -histo <pid>
```

## 3. Explicit heavy artifact collection

Heavy artifacts require `--java-deep` plus a second explicit flag:

```bash
oi mem -s 14d -m inv --java-deep --heap-dump
oi mem -s 14d -m inv --java-deep --jfr-dump
```

Artifacts are written under:

```text
.oi/cases/<case-id>/artifacts/jvm/<pid>/
  thread-print.txt
  class-histogram.txt
  heap.hprof
  recording.jfr
```

Heap dumps can be large and may pause or pressure the target JVM. JFR dump export depends on an existing recording and local JVM permissions.

## Policy boundary

`oi sh` and AI `oi_ro_run` cannot bypass these gates. The read-only shell policy denies:

```text
jcmd <pid> GC.heap_dump ...
jcmd <pid> JFR.dump ...
jmap -dump ...
```

Use the explicit `--java-deep --heap-dump` or `--java-deep --jfr-dump` collectors when artifact collection has been approved.
