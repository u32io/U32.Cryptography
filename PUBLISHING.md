# Publishing

Package the project
```shell
cd U32.Cryptography
dotnet pack -c:Release
```

Publish a release to nuget.org.
```shell
cd bin/Release
dotnet nuget push U32.Cryptography.$VERSION.nupkg --api-key $API_KEY --source https://api.nuget.org/v3/index.json
```