```
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:AllowUnsafeBlocks=true
```
```
csc /out:tool_csharp.exe Program.cs /reference:System.Windows.Forms.dll /target:winexe /unsafe
```