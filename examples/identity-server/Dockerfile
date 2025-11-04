FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["IdentityServer.csproj", "."]
RUN dotnet restore "./IdentityServer.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "IdentityServer.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "IdentityServer.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Copy and setup startup script
COPY startup.sh /app/startup.sh
RUN chmod +x /app/startup.sh

# Create non-root user and switch to it
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["/app/startup.sh"]