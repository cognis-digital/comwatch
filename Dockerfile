# comwatch — container image
# Multi-stage: build with the SDK, ship on the smaller runtime image.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY comwatch.csproj ./
RUN dotnet restore comwatch.csproj
COPY src/ ./src/
RUN dotnet publish comwatch.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
LABEL org.opencontainers.image.title="comwatch" \
      org.opencontainers.image.description="COM-hijack & persistence detector for Windows registry exports" \
      org.opencontainers.image.source="https://github.com/cognis-digital/comwatch" \
      org.opencontainers.image.licenses="LicenseRef-COCL-1.0"
WORKDIR /work
COPY --from=build /app /opt/comwatch
# comwatch reads .reg text — mount your exports into /work and pass paths / stdin.
ENTRYPOINT ["dotnet", "/opt/comwatch/comwatch.dll"]
CMD ["--help"]
