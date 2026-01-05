zig-x86_64-windows-0.16.0-dev.1912+0cbaaa5eb

```
zig build -Doptimize=ReleaseFast
```

```
zig build-exe src/main.zig -O ReleaseFast -fstrip --subsystem console
```