# Sidub Platform - Authentication - SignalR

This repository contains the SignalR authentication library for the Sidub
Platform. It supports authentication when communicating with SignalR
data services.

## Main Components
To use the SignalR authentication module, you can register it within your
dependency injection container.

```csharp
public void ConfigureServices(IServiceCollection services)
{
  services.AddSidubAuthenticationForSignalR();
}
```

## License
This project is dual-licensed under the AGPL v3 or a proprietary license. For
details, see [https://sidub.ca/licensing](https://sidub.ca/licensing) or the 
LICENSE.txt file.
